/* This file is part of VoltDB.
 * Copyright (C) 2008-2014 VoltDB Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with VoltDB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "ExprGenerator.hpp"

#include "codegen/CodegenContextImpl.hpp"
#include "common/ValuePeeker.hpp"
#include "expressions/abstractexpression.h"
#include "expressions/comparisonexpression.h"
#include "expressions/operatorexpression.h"


namespace voltdb {

    namespace {

        // Bundles an llvm::Value* with may-be-null meta-data.
        class CGValue {
        public:
            CGValue(llvm::Value* val, bool mayBeNull)
                : m_value(val)
                , m_mayBeNull(mayBeNull)
            {
            }

            llvm::Value* val() const {
                return m_value;
            }

            bool mayBeNull() const {
                return m_mayBeNull;
            }

        private:
            llvm::Value* m_value;
            bool m_mayBeNull;
        };

        // This should not really be necessary, but sometimes the
        // NValue produced by an expression's eval() method does not
        // match the ValueType produced by calling
        // expr->getValueType().  This function is provided to work
        // around this.
        ValueType getExprType(const AbstractExpression* expr) {
            switch (expr->getExpressionType()) {
            case EXPRESSION_TYPE_COMPARE_EQUAL:
            case EXPRESSION_TYPE_COMPARE_NOTEQUAL:
            case EXPRESSION_TYPE_COMPARE_LESSTHAN:
            case EXPRESSION_TYPE_COMPARE_GREATERTHAN:
            case EXPRESSION_TYPE_COMPARE_LESSTHANOREQUALTO:
            case EXPRESSION_TYPE_COMPARE_GREATERTHANOREQUALTO:
            case EXPRESSION_TYPE_COMPARE_LIKE:
            case EXPRESSION_TYPE_COMPARE_IN:
            case EXPRESSION_TYPE_CONJUNCTION_AND:
            case EXPRESSION_TYPE_CONJUNCTION_OR:
                return VALUE_TYPE_BOOLEAN;
            default:
                return expr->getValueType();
            }
        }

        llvm::Value* getNullValueForType(llvm::Type* ty) {
            if (!ty->isIntegerTy()) {
                throw UnsupportedForCodegenException("attempt to get null value for non-integer type");
            }

            llvm::IntegerType* intTy = static_cast<llvm::IntegerType*>(ty);
            unsigned bitWidth = intTy->getBitWidth();
            switch (bitWidth) {
            case 8:
                return llvm::ConstantInt::get(intTy, INT8_NULL);
            case 16:
                return llvm::ConstantInt::get(intTy, INT16_NULL);
            case 32:
                return llvm::ConstantInt::get(intTy, INT32_NULL);
            default:
                assert (bitWidth == 64);
                return llvm::ConstantInt::get(intTy, INT64_NULL);
            }
        }
    }

    ExprGenerator::ExprGenerator(CodegenContextImpl* codegenContext,
                                 llvm::Function* function,
                                 llvm::IRBuilder<>* builder,
                                 llvm::Value* tupleArg)
        : m_codegenContext(codegenContext)
        , m_function(function)
        , m_builder(builder)
        , m_tupleArg(tupleArg)
    {
    }

    llvm::Value*
    ExprGenerator::generate(const TupleSchema* schema,
                            const AbstractExpression* expr) {
        return codegenExpr(schema, expr).val();
    }

    llvm::IRBuilder<>& ExprGenerator::builder() {
        return *m_builder;
    }

    llvm::Type* ExprGenerator::getLlvmType(ValueType voltType) {
        return m_codegenContext->getLlvmType(voltType);
    }

    llvm::Value* ExprGenerator::getTupleArg() {
        return m_tupleArg;
    }

    llvm::Type* ExprGenerator::getIntPtrType() {
        return m_codegenContext->getIntPtrType();
    }

    llvm::LLVMContext& ExprGenerator::getLlvmContext() {
        return m_codegenContext->getLlvmContext();
    }


    CGValue
    ExprGenerator::codegenParameterValueExpr(const TupleSchema*,
                                             const ParameterValueExpression* expr) {
        llvm::Constant* nvalueAddrAsInt = llvm::ConstantInt::get(getIntPtrType(),
                                                                 (uintptr_t)expr->getParamValue());

        // cast the pointer to the nvalue as a pointer to the value.
        // Since the first member of NValue is the 16-byte m_data
        // array, this is okay for all the numeric types.  But if
        // NValue ever changes, this code will break.
        llvm::PointerType* ptrTy = llvm::PointerType::getUnqual(getLlvmType(getExprType(expr)));
        llvm::Value* castedAddr = builder().CreateIntToPtr(nvalueAddrAsInt, ptrTy);

        std::ostringstream varName;
        varName << "param_" << expr->getValueIdx();
        return CGValue(builder().CreateLoad(castedAddr, varName.str().c_str()),
                       true); // true means value may be null
    }

    CGValue
    ExprGenerator::codegenTupleValueExpr(const TupleSchema* schema,
                                         const TupleValueExpression* expr) {
        // find the offset of the field in the record
        const TupleSchema::ColumnInfo *columnInfo = schema->getColumnInfo(expr->getColumnId());
        uint32_t intOffset = TUPLE_HEADER_SIZE + columnInfo->offset;
        llvm::Value* offset = llvm::ConstantInt::get(getLlvmType(VALUE_TYPE_INTEGER), intOffset);

        // emit instruction that computes the address of the value
        // GEP is getelementptr, which amounts here to a pointer add.
        llvm::Value* addr = builder().CreateGEP(getTupleArg(),
                                                offset);
        // Cast addr from char* to the appropriate pointer type
        // An LLVM IR instruction is created but it will be a no-op on target
        llvm::Type* ptrTy = llvm::PointerType::getUnqual(getLlvmType(getExprType(expr)));
        llvm::Value* castedAddr = builder().CreateBitCast(addr,
                                                          ptrTy);
        std::ostringstream varName;
        varName << "field_" << expr->getColumnId();
        return CGValue(builder().CreateLoad(castedAddr, varName.str().c_str()),
                       columnInfo->allowNull);
    }

    llvm::Value*
    ExprGenerator::codegenCmpOp(ExpressionType exprType,
                                ValueType outputType,
                                llvm::Value* lhs,
                                llvm::Value* rhs) {
        // For floating point types, we would CreateFCmp* here instead...

        llvm::Value* cmp = NULL;
        switch (exprType) {
        case EXPRESSION_TYPE_COMPARE_EQUAL:
            cmp = builder().CreateICmpEQ(lhs, rhs);
            break;
        case EXPRESSION_TYPE_COMPARE_NOTEQUAL:
            cmp = builder().CreateICmpNE(lhs, rhs);
            break;
        case EXPRESSION_TYPE_COMPARE_LESSTHAN:
            cmp = builder().CreateICmpSLT(lhs, rhs);
            break;
        case EXPRESSION_TYPE_COMPARE_GREATERTHAN:
            cmp = builder().CreateICmpSGT(lhs, rhs);
            break;
        case EXPRESSION_TYPE_COMPARE_LESSTHANOREQUALTO:
            cmp = builder().CreateICmpSLE(lhs, rhs);
            break;
        case EXPRESSION_TYPE_COMPARE_GREATERTHANOREQUALTO:
            cmp = builder().CreateICmpSGE(lhs, rhs);
            break;
        default:
            throw UnsupportedForCodegenException(expressionToString(exprType));
        }

        // LLVM icmp and fcmp instructions produce a 1-bit integer
        // Zero-extend to 8 bits.
        return builder().CreateZExt(cmp, getLlvmType(outputType));
    }

    llvm::Value*
    ExprGenerator::getTrueValue() {
        return llvm::ConstantInt::get(getLlvmType(VALUE_TYPE_BOOLEAN), 1);
    }

    llvm::Value*
    ExprGenerator::getFalseValue() {
        return llvm::ConstantInt::get(getLlvmType(VALUE_TYPE_BOOLEAN), 0);
    }

    llvm::Value*
    ExprGenerator::compareToNull(llvm::Value* val) {
        return builder().CreateICmpEQ(val, getNullValueForType(val->getType()));
    }

    llvm::BasicBlock*
    ExprGenerator::getEmptyBasicBlock(const std::string& label) {
        return llvm::BasicBlock::Create(getLlvmContext(), label, m_function);
    }

    typedef std::pair<llvm::Value*, llvm::BasicBlock*> ValueBB;

    CGValue
    ExprGenerator::codegenConjunctionAndExpr(const TupleSchema* tupleSchema,
                                             const AbstractExpression* expr) {

        //     lhs   AND    rhs
        //
        //   eval lhs
        //   if (lhs == false)
        //       answer = false
        //       goto result
        //
        //   eval rhs
        //   if (lhs == true)
        //       answer = rhs
        //       goto result
        //
        //   // lhs is unknown
        //   if (rhs == false)
        //       answer = false
        //       goto result
        //
        //   answer = unknown
        //   goto result
        //
        // result:
        //   return phi(answer)

        std::vector<ValueBB> results;
        llvm::BasicBlock* resultBlock = getEmptyBasicBlock("and_result");
        CGValue left = codegenExpr(tupleSchema,
                                   expr->getLeft());
        llvm::BasicBlock *lhsFalseLabel = getEmptyBasicBlock("and_lhs_false");
        llvm::BasicBlock *lhsNotFalseLabel = getEmptyBasicBlock("and_lhs_not_false");
        llvm::Value* lhsFalseCmp = builder().CreateICmpEQ(left.val(), getFalseValue());
        builder().CreateCondBr(lhsFalseCmp, lhsFalseLabel, lhsNotFalseLabel);

        builder().SetInsertPoint(lhsFalseLabel);
        results.push_back(std::make_pair(getFalseValue(), lhsFalseLabel));
        builder().CreateBr(resultBlock);

        builder().SetInsertPoint(lhsNotFalseLabel);
        CGValue right = codegenExpr(tupleSchema,
                                    expr->getRight());
        if (! left.mayBeNull()) {
            // lhs cannot be null, so it must be true.
            // Answer is whatever rhs is.
            results.push_back(std::make_pair(right.val(), lhsNotFalseLabel));
            builder().CreateBr(resultBlock);
        }
        else {
            llvm::BasicBlock *lhsTrueLabel = getEmptyBasicBlock("and_lhs_true");
            llvm::BasicBlock *lhsNullLabel = getEmptyBasicBlock("and_lhs_null");
            llvm::Value* lhsTrueCmp = builder().CreateICmpEQ(left.val(), getTrueValue());
            builder().CreateCondBr(lhsTrueCmp, lhsTrueLabel, lhsNullLabel);


            builder().SetInsertPoint(lhsTrueLabel);
            results.push_back(std::make_pair(right.val(), lhsTrueLabel));
            builder().CreateBr(resultBlock);

            // lhs is null

            builder().SetInsertPoint(lhsNullLabel);
            llvm::BasicBlock *rhsFalseLabel = getEmptyBasicBlock("and_rhs_false");
            llvm::BasicBlock *rhsNotFalseLabel = getEmptyBasicBlock("and_rhs_not_false");
            llvm::Value* rhsFalseCmp = builder().CreateICmpEQ(right.val(), getFalseValue());
            builder().CreateCondBr(rhsFalseCmp, rhsFalseLabel, rhsNotFalseLabel);

            // rhs false, so result is false
            builder().SetInsertPoint(rhsFalseLabel);
            results.push_back(std::make_pair(getFalseValue(), rhsFalseLabel));
            builder().CreateBr(resultBlock);

            // rhs is not false, so result is unknown
            builder().SetInsertPoint(rhsNotFalseLabel);
            results.push_back(std::make_pair(getNullValueForType(getLlvmType(getExprType(expr))),
                                             rhsNotFalseLabel));
            builder().CreateBr(resultBlock);
        }

        resultBlock->moveAfter(builder().GetInsertBlock());
        builder().SetInsertPoint(resultBlock);

        llvm::PHINode* phi = builder().CreatePHI(getLlvmType(getExprType(expr)), 3);

        std::vector<ValueBB>::iterator it = results.begin();
        for(; it != results.end(); ++it) {
            phi->addIncoming(it->first, it->second);
        }

        bool mayBeNull = left.mayBeNull() || right.mayBeNull();
        return CGValue(phi,
                       mayBeNull);
    }

    // Sign-extend one side to the width of the wider side.
    // This will only work if lhs/rhs values are NOT NULL!
    std::pair<llvm::Value*, llvm::Value*> ExprGenerator::homogenizeTypes(llvm::Value* lhs, llvm::Value* rhs) {
        llvm::IntegerType* lhsTy = llvm::dyn_cast<llvm::IntegerType>(lhs->getType());
        llvm::IntegerType* rhsTy = llvm::dyn_cast<llvm::IntegerType>(rhs->getType());

        if (lhsTy->getBitWidth() > rhsTy->getBitWidth()) {
            return std::make_pair(lhs,
                                  builder().CreateSExt(rhs, lhsTy));
        }
        else if (rhsTy->getBitWidth() > lhsTy->getBitWidth()) {
            return std::make_pair(builder().CreateSExt(lhs, rhsTy),
                                  rhs);
        }

        // types already homogenized.
        return std::make_pair(lhs, rhs);
    }

    CGValue
    ExprGenerator::codegenComparisonExpr(const TupleSchema* tupleSchema,
                                         const AbstractExpression* expr) {

        std::vector<ValueBB> results;
        llvm::BasicBlock* resultBlock = getEmptyBasicBlock("cmp_result");
        CGValue left = codegenExpr(tupleSchema,
                                   expr->getLeft());
        if (left.mayBeNull()) { // value produced on LHS may be null
            llvm::BasicBlock* lhsIsNull = getEmptyBasicBlock("cmp_lhs_null");
            llvm::BasicBlock* lhsNotNull = getEmptyBasicBlock("cmp_lhs_not_null");
            llvm::Value* cmp = compareToNull(left.val());
            builder().CreateCondBr(cmp, lhsIsNull, lhsNotNull);

            builder().SetInsertPoint(lhsIsNull);
            results.push_back(std::make_pair(getNullValueForType(getLlvmType(VALUE_TYPE_BOOLEAN)),
                                             lhsIsNull));
            builder().CreateBr(resultBlock);

            builder().SetInsertPoint(lhsNotNull);
        }

        CGValue right = codegenExpr(tupleSchema,
                                    expr->getRight());
        if (right.mayBeNull()) { // value produced on RHS may be null
            llvm::BasicBlock* rhsIsNull = getEmptyBasicBlock("cmp_rhs_null");
            llvm::BasicBlock* rhsNotNull = getEmptyBasicBlock("cmp_rhs_not_null");
            llvm::Value* cmp = compareToNull(right.val());
            builder().CreateCondBr(cmp, rhsIsNull, rhsNotNull);

            builder().SetInsertPoint(rhsIsNull);
            results.push_back(std::make_pair(getNullValueForType(getLlvmType(VALUE_TYPE_BOOLEAN)),
                                             rhsIsNull));
            builder().CreateBr(resultBlock);

            builder().SetInsertPoint(rhsNotNull);
        }

        // Types on both sides may not be the same.
        std::pair<llvm::Value*, llvm::Value*> lhsRhs;
        lhsRhs = homogenizeTypes(left.val(), right.val());

        llvm::Value* cmp = codegenCmpOp(expr->getExpressionType(),
                                        getExprType(expr),
                                        lhsRhs.first,
                                        lhsRhs.second);
        results.push_back(std::make_pair(cmp, builder().GetInsertBlock()));
        builder().CreateBr(resultBlock);

        resultBlock->moveAfter(builder().GetInsertBlock());
        builder().SetInsertPoint(resultBlock);
        llvm::PHINode* phi = builder().CreatePHI(getLlvmType(getExprType(expr)), 3);

        std::vector<ValueBB>::iterator it = results.begin();
        for(; it != results.end(); ++it) {
            phi->addIncoming(it->first, it->second);
        }

        bool mayBeNull = left.mayBeNull() || right.mayBeNull();
        return CGValue(phi,
                       mayBeNull);
    }

    CGValue
    ExprGenerator::codegenIsNullExpr(const TupleSchema* tupleSchema,
                                     const OperatorIsNullExpression* expr) {
        CGValue child = codegenExpr(tupleSchema,
                                    expr->getLeft());
        if (! child.mayBeNull()) {
            // argument is never null, is isNull is always false here.
            return CGValue(getFalseValue(), false);
        }

        llvm::Value* cmp = compareToNull(child.val());
        return CGValue(builder().CreateZExt(cmp, getLlvmType(VALUE_TYPE_BOOLEAN)),
                       false); // result will never be null
    }

    CGValue
    ExprGenerator::codegenConstantValueExpr(const TupleSchema*,
                                            const ConstantValueExpression* expr) {
        // constant value should never need to access tuples,
        // so it should be ok to just pass nulls here.
        NValue nval = expr->eval(NULL, NULL);
        llvm::Type* ty = getLlvmType(ValuePeeker::peekValueType(nval));
        if (nval.isNull()) {
            return CGValue(getNullValueForType(ty),
                           true);
        }

        llvm::Value* k = llvm::ConstantInt::get(ty,
                                                ValuePeeker::peekAsBigInt(nval));
        return CGValue(k, false); // never null if we get here.
    }

    CGValue
    ExprGenerator::codegenExpr(const TupleSchema* tupleSchema,
                               const AbstractExpression* expr) {
        ExpressionType exprType = expr->getExpressionType();
        switch (exprType) {
        case EXPRESSION_TYPE_COMPARE_EQUAL:
        case EXPRESSION_TYPE_COMPARE_NOTEQUAL:
        case EXPRESSION_TYPE_COMPARE_LESSTHAN:
        case EXPRESSION_TYPE_COMPARE_GREATERTHAN:
        case EXPRESSION_TYPE_COMPARE_LESSTHANOREQUALTO:
        case EXPRESSION_TYPE_COMPARE_GREATERTHANOREQUALTO:
        case EXPRESSION_TYPE_COMPARE_LIKE:
        case EXPRESSION_TYPE_COMPARE_IN:
            return codegenComparisonExpr(tupleSchema, expr);
        case EXPRESSION_TYPE_OPERATOR_IS_NULL:
            return codegenIsNullExpr(tupleSchema, static_cast<const OperatorIsNullExpression*>(expr));
        case EXPRESSION_TYPE_CONJUNCTION_AND:
            return codegenConjunctionAndExpr(tupleSchema, expr);
        case EXPRESSION_TYPE_VALUE_TUPLE:
            return codegenTupleValueExpr(tupleSchema, static_cast<const TupleValueExpression*>(expr));
        case EXPRESSION_TYPE_VALUE_PARAMETER:
            return codegenParameterValueExpr(tupleSchema, static_cast<const ParameterValueExpression*>(expr));
        case EXPRESSION_TYPE_VALUE_CONSTANT:
            return codegenConstantValueExpr(tupleSchema, static_cast<const ConstantValueExpression*>(expr));
        default:
            throw UnsupportedForCodegenException(expressionToString(exprType));
        }
    }
}
