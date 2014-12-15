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

// Uncomment this to get informative debug messages
// regarding codegen
//
#ifdef VOLT_LOG_LEVEL
#undef VOLT_LOG_LEVEL
#endif

#define VOLT_LOG_LEVEL VOLT_LEVEL_DEBUG

#include "codegen/CodegenContextImpl.hpp"
#include "codegen/ExprGenerator.hpp"
#include "common/SQLException.h"
#include "common/TupleSchema.h"
#include "common/debuglog.h"
#include "common/types.h"
#include "common/value_defs.h"
#include "common/ValuePeeker.hpp"
#include "executors/abstractexecutor.h"
#include "expressions/abstractexpression.h"
#include "expressions/comparisonexpression.h"
#include "expressions/operatorexpression.h"

#include "llvm/Analysis/Passes.h"
#include "llvm/Analysis/Verifier.h"
#include "llvm/ExecutionEngine/ExecutionEngine.h"
#include "llvm/ExecutionEngine/JIT.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/PassManager.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/Scalar.h"

#include "boost/timer.hpp"

static pthread_once_t llvmNativeTargetInitialized = PTHREAD_ONCE_INIT;

static void initializeNativeTarget() {
    (void)llvm::InitializeNativeTarget();
}

namespace voltdb {

    static llvm::Value* getNullValueForType(llvm::Type* ty) {
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

    // This should not really be necessary, but sometimes the NValue
    // produced by an expression's eval() method does not match the
    // ValueType produced by calling expr->getValueType().  This
    // function is provided to work around this.
    static ValueType getExprType(const AbstractExpression* expr) {
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

        // maintains the current state of the LLVM function being generated
        class PredFnCtx {
        public:
            // Create a function context for a function that
            //   accepts a pointer to a tuple
            //   returns a boolean
            //   has external linkage (can be called from outside llvm module)
            PredFnCtx(CodegenContextImpl* codegenContext, const std::string& name)
                : m_codegenContext(codegenContext)
                , m_function(NULL)
                , m_builder()
            {
                init(name, llvm::Function::ExternalLinkage, VALUE_TYPE_BOOLEAN);
            }

            void codegen(const TupleSchema* tupleSchema,
                         const AbstractExpression* expr) {
                ExprGenerator generator(m_codegenContext, m_function, m_builder.get(), getTupleArg());
                llvm::Value* answer = generator.generate(tupleSchema, expr);
                builder().CreateRet(answer);
            }

            llvm::Function* getFunction() {
                return m_function;
            }

        private:

            // alternate constructor to allow creating function with
            // internal linkage (can only be called from other LLVM
            // functions)
            PredFnCtx(CodegenContextImpl* codegenContext,
                  const std::string& name,
                  llvm::Function::LinkageTypes linkage,
                  ValueType returnTy)
                : m_codegenContext(codegenContext)
                , m_function(NULL)
                , m_builder()
            {
                init(name, linkage, returnTy);
            }

            void init(const std::string& name,
                      llvm::Function::LinkageTypes linkage,
                      ValueType returnTy) {
                llvm::LLVMContext &ctx = getLlvmContext();

                std::vector<llvm::Type*> argType(1, llvm::Type::getInt8PtrTy(ctx));
                llvm::Type* retType = getLlvmType(returnTy);
                llvm::FunctionType* ft = llvm::FunctionType::get(retType, argType, false);
                m_function = llvm::Function::Create(ft,
                                                    linkage,
                                                    name,
                                                    m_codegenContext->getModule());

                m_function->arg_begin()->setName("tuple");

                llvm::BasicBlock *bb = llvm::BasicBlock::Create(ctx, "entry", m_function);
                m_builder.reset(new llvm::IRBuilder<>(bb));
            }


            llvm::IRBuilder<>& builder() {
                return *m_builder;
            }

            llvm::Type* getIntPtrType() {
                return m_codegenContext->getIntPtrType();
            }

            llvm::Type* getLlvmType(ValueType voltType) {
                return m_codegenContext->getLlvmType(voltType);
            }

            llvm::Value* getTupleArg() {
                return m_function->arg_begin();
            }

            llvm::LLVMContext& getLlvmContext() {
                return m_codegenContext->getLlvmContext();
            }

            CGValue
            codegenParameterValueExpr(const TupleSchema*,
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
            codegenTupleValueExpr(const TupleSchema* schema,
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
            codegenCmpOp(ExpressionType exprType,
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
            getTrueValue() {
                return llvm::ConstantInt::get(getLlvmType(VALUE_TYPE_BOOLEAN), 1);
            }

            llvm::Value*
            getFalseValue() {
                return llvm::ConstantInt::get(getLlvmType(VALUE_TYPE_BOOLEAN), 0);
            }

            llvm::Value* compareToNull(llvm::Value* val) {
                return builder().CreateICmpEQ(val, getNullValueForType(val->getType()));
            }

            llvm::BasicBlock* getEmptyBasicBlock(const std::string& label) {
                return llvm::BasicBlock::Create(getLlvmContext(), label, m_function);
            }

            typedef std::pair<llvm::Value*, llvm::BasicBlock*> ValueBB;

            CGValue
            codegenConjunctionAndExpr(const TupleSchema* tupleSchema,
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
            std::pair<llvm::Value*, llvm::Value*> homogenizeTypes(llvm::Value* lhs, llvm::Value* rhs) {
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
            codegenComparisonExpr(const TupleSchema* tupleSchema,
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
            codegenIsNullExpr(const TupleSchema* tupleSchema,
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
            codegenConstantValueExpr(const TupleSchema*,
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
            codegenExpr(const TupleSchema* tupleSchema,
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



            CodegenContextImpl* m_codegenContext;
            llvm::Function* m_function;
            boost::scoped_ptr<llvm::IRBuilder<> > m_builder;
        };

        class PlanNodeFnCtx {
        public:
            PlanNodeFnCtx(CodegenContextImpl* codegenContext, AbstractExecutor* executor)
                : m_codegenContext(codegenContext)
                , m_function(NULL)
                , m_builder()
                , m_node(executor->getPlanNode())
            {
            }

            void init() {
                llvm::LLVMContext &ctx = getLlvmContext();

                // Function prototype for a plan node looks like
                //
                // bool
                // planNodeFunction(Table* inTable, Table* outTable);
                //
                // represent the tables as void* for now.

                std::ostringstream name;
                name << planNodeToString(m_node->getPlanNodeType()) << "_"
                     << m_node->getPlanNodeId() << "_execute";

                llvm::Type* ptrTy = llvm::Type::getInt8PtrTy(ctx);
                std::vector<llvm::Type*> argTypes(2, ptrTy);
                llvm::Type* retType = llvm::Type::getInt8Ty(ctx);

                // False means that this type is not a vararg function type.
                llvm::FunctionType* ft = llvm::FunctionType::get(retType, argTypes, false);

                m_function = llvm::Function::Create(ft,
                                                    llvm::Function::ExternalLinkage,
                                                    name.str(),
                                                    m_codegenContext->getModule());
                m_function->getArgumentList().front().setName("in_table");
                m_function->getArgumentList().back().setName("out_table");
                llvm::BasicBlock *bb = llvm::BasicBlock::Create(ctx, "entry", m_function);

                m_builder.reset(new llvm::IRBuilder<>(bb));
            }

            void codegen() {
                llvm::LLVMContext &ctx = getLlvmContext();
                llvm::Value* retValue = llvm::ConstantInt::get(llvm::Type::getInt8Ty(ctx), 1);
                builder().CreateRet(retValue);
            }

            llvm::Function* getFunction() const {
                return m_function;
            }

        private:

            llvm::LLVMContext& getLlvmContext() {
                return m_codegenContext->getLlvmContext();
            }

            llvm::IRBuilder<>& builder() {
                return *m_builder;
            }

            CodegenContextImpl* m_codegenContext;
            llvm::Function* m_function;
            boost::scoped_ptr<llvm::IRBuilder<> > m_builder;
            AbstractPlanNode *m_node;
        };
    }

    CodegenContextImpl::CodegenContextImpl()
        : m_llvmContext()
        , m_module(NULL)
        , m_executionEngine()
        , m_passManager()
        , m_errorString()
    {
        // This really only needs to be called once for the whole process.
        (void) pthread_once(&llvmNativeTargetInitialized, initializeNativeTarget);

        m_llvmContext.reset(new llvm::LLVMContext());

        m_module = new llvm::Module("voltdb_generated_code", *m_llvmContext);

        llvm::ExecutionEngine *engine = llvm::EngineBuilder(m_module).setErrorStr(&m_errorString).create();

        if (! engine) {
            // throwing in a constructor is bad
            // all of this should be in an init method
            // should also release module in this case.
            throw std::exception();
        }

        // m_module now owned by the engine.

        m_executionEngine.reset(engine);

        m_passManager.reset(new llvm::FunctionPassManager(m_module));

        m_passManager->add(new llvm::DataLayout(*m_executionEngine->getDataLayout()));

        //m_passManager->add(llvm::createFunctionInliningPass());

        // Do simple "peephole" optimizations and bit-twiddling optzns.
        m_passManager->add(llvm::createInstructionCombiningPass());
        // Reassociate expressions.
        m_passManager->add(llvm::createReassociatePass());
        // Eliminate Common SubExpressions.
        m_passManager->add(llvm::createGVNPass());
        // Simplify the control flow graph (deleting unreachable blocks, etc).
        m_passManager->add(llvm::createCFGSimplificationPass());

        m_passManager->doInitialization();
    }

    CodegenContextImpl::~CodegenContextImpl() {
    }

    llvm::LLVMContext&
    CodegenContextImpl::getLlvmContext() {
        return *m_llvmContext;
    }

    llvm::Module*
    CodegenContextImpl::getModule() {
        return m_module;
    }

    llvm::Type*
    CodegenContextImpl::getLlvmType(ValueType voltType) {
        llvm::LLVMContext &ctx = *m_llvmContext;
        switch (voltType) {
        case VALUE_TYPE_TINYINT:
            return llvm::Type::getInt8Ty(ctx);
        case VALUE_TYPE_SMALLINT:
            return llvm::Type::getInt16Ty(ctx);
        case VALUE_TYPE_INTEGER:
            return llvm::Type::getInt32Ty(ctx);
        case VALUE_TYPE_BIGINT:
            return llvm::Type::getInt64Ty(ctx);
        case VALUE_TYPE_TIMESTAMP:
            return llvm::Type::getInt64Ty(ctx);
        case VALUE_TYPE_BOOLEAN:
            return llvm::Type::getInt8Ty(ctx);
        default: {
            std::ostringstream oss;
            oss << "expression with type " << valueToString(voltType);
            throw UnsupportedForCodegenException(oss.str());
        }
        }
    }

    llvm::IntegerType* CodegenContextImpl::getIntPtrType() {
        return m_executionEngine->getDataLayout()->getIntPtrType(*m_llvmContext);
    }

    static void dumpModule(llvm::Module* module, const std::string& desc) {
#if VOLT_LOG_LEVEL<=VOLT_LEVEL_DEBUG
        std::string irDump;
        llvm::raw_string_ostream rso(irDump);
        module->print(rso, NULL);
        VOLT_DEBUG("%s LLVM IR in module: \n%s", desc.c_str(), irDump.c_str());
#else
        (void)module;
#endif
    }

    void*
    CodegenContextImpl::generateCode(llvm::Function* fn) {
        void* nativeFunction = NULL;
        boost::timer t;

        // Dump the unoptimized fn
        dumpModule(m_module, "Unoptimized");

        // This will throw an exception if we did anything wonky in LLVM IR
        t.restart();
        llvm::verifyFunction(*fn);
        VOLT_DEBUG("Verification of IR took %f seconds", t.elapsed());

        // This will optimize the function
        t.restart();
        m_passManager->run(*fn);
        VOLT_DEBUG("Optimization took %f seconds", t.elapsed());

        // Finally generate the actual code
        t.restart();
        nativeFunction = m_executionEngine->getPointerToFunction(fn);
        VOLT_DEBUG("Native code generation took %f seconds", t.elapsed());

        // Dump optimized LLVM IR
        dumpModule(m_module, "Optimized");

        return nativeFunction;
    }

    PredFunction
    CodegenContextImpl::compilePredicate(const std::string& fnName,
                                     const TupleSchema* tupleSchema,
                                     const AbstractExpression* expr) {
        VOLT_DEBUG("Attempting to compile predicate:\n%s", expr->debug(true).c_str());
        PredFnCtx predFnCtx(this, fnName);
        boost::timer t;

        try {
            t.restart();
            predFnCtx.codegen(tupleSchema, expr);
            VOLT_DEBUG("Predicate IR construction took %f seconds", t.elapsed());
        }
        catch (UnsupportedForCodegenException& ex) {
            predFnCtx.getFunction()->eraseFromParent();
            VOLT_DEBUG("Aborted compilation: %s", ex.getMessage().c_str());

            // EE will fall back to interpreting function
            return NULL;
        }

        return (PredFunction)generateCode(predFnCtx.getFunction());
    }

    PlanNodeFunction
    CodegenContextImpl::compilePlanNode(AbstractExecutor *executor) {
        VOLT_DEBUG("Attempting to compile plan node:\n%s", executor->getPlanNode()->debug().c_str());
        PlanNodeFnCtx planNodeFnCtx(this, executor);
        planNodeFnCtx.init();
        boost::timer t;

        try {
            t.restart();
            planNodeFnCtx.codegen();
            VOLT_DEBUG("Plan node IR construction took %f seconds", t.elapsed());
        }
        catch (UnsupportedForCodegenException& ex) {
            planNodeFnCtx.getFunction()->eraseFromParent();
            VOLT_DEBUG("Aborted compilation: %s", ex.getMessage().c_str());

            // EE will fall back to interpreting function
            return NULL;
        }

        return (PlanNodeFunction)generateCode(planNodeFnCtx.getFunction());
    }

    void CodegenContextImpl::shutdownLlvm() {
        llvm::llvm_shutdown();
    }
}
