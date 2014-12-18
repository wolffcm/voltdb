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

#define VOLT_LOG_LEVEL VOLT_LEVEL_TRACE

#include "ExprGenerator.hpp"

#include "llvm/IR/Function.h"
#include "llvm/IR/Intrinsics.h"

#include "codegen/CodegenContextImpl.hpp"
#include "common/ValuePeeker.hpp"
#include "expressions/abstractexpression.h"
#include "expressions/comparisonexpression.h"
#include "expressions/operatorexpression.h"


namespace voltdb {

    namespace {

        bool voltTrace() {
#if VOLT_LOG_LEVEL<=VOLT_LEVEL_TRACE
            return true;
#else
            return false;
#endif
        }

        llvm::Value* getNullValueForType(llvm::Type* ty) {
            VOLT_TRACE("Entering");
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



        llvm::Value*
        getInlinedVarcharLength(llvm::IRBuilder<>& builder, const CGValue& vcVal) {
            assert(vcVal.isInlinedVarchar());

            // load the first byte
            llvm::Value* fb = builder.CreateLoad(vcVal.val());
            const char mask = ~static_cast<char>(OBJECT_NULL_BIT | OBJECT_CONTINUATION_BIT);
            llvm::Value* len = builder.CreateAnd(fb, mask);
            len = builder.CreateZExt(len, getNativeSizeType(len->getContext()));
            return len;
        }

        llvm::Value* getInlinedVarcharData(llvm::IRBuilder<>& builder, const CGValue& vcVal) {
            assert(vcVal.isInlinedVarchar());
            return builder.CreateConstGEP1_32(vcVal.val(), 1);
        }

        // void callDebugPtr(CodegenContextImpl* cgCtx,
        //                   llvm::IRBuilder<>& builder,
        //                   size_t num,
        //                llvm::Value* val) {
        //     if (voltTrace()) {
        //         assert (llvm::isa<llvm::PointerType>(val->getType()));

        //         llvm::Value* casted = builder.CreateBitCast(val, builder.getInt8PtrTy());

        //         llvm::Function* fn = cgCtx->getFunction("codegen_debug_ptr");
        //         builder.CreateCall2(fn, builder.getInt64(num), casted);
        //     }
        // }

        void callDebugSize(CodegenContextImpl* cgCtx,
                          llvm::IRBuilder<>& builder,
                          size_t num,
                       llvm::Value* val) {
            if (voltTrace()) {
                assert (val->getType() == getNativeSizeType(val->getContext()));
                llvm::Function* fn = cgCtx->getFunction("codegen_debug_size");
                builder.CreateCall2(fn, builder.getInt64(num), val);
            }
        }

        // Returns a pointer to the length prefix
        llvm::Value* getOutlinedVarcharBuffer(CodegenContextImpl* cgCtx,
                                              llvm::IRBuilder<>& builder,
                                              const CGValue& vcVal) {
            llvm::Function* stringRefGetFn = cgCtx->getFunction("stringref_get");
            llvm::Value* buffer = builder.CreateCall(stringRefGetFn, vcVal.val(), "outl_vc_buf");
            return buffer;

            // The following code attempts to inline StringRef::get
            // It is buggy!
            //
            // assert (vcVal.val()->getType() == getPtrToStringRefType(ctx));
            // callDebug(cgCtx, builder, 50, vcVal.val());

            // // get a pointer StringRef's first field
            // llvm::Value* ptrToPtrToBuffer = builder.CreateStructGEP(vcVal.val(), 0);
            // // should be pointer to pointer
            // assert (ptrToPtrToBuffer->getType() ==
            //         llvm::PointerType::getUnqual(builder.getInt8PtrTy()));
            // callDebug(cgCtx, builder, 51, ptrToPtrToBuffer);

            // llvm::Value* ptrToBuffer = builder.CreateLoad(ptrToPtrToBuffer);
            // assert (ptrToBuffer->getType() == builder.getInt8PtrTy());
            // callDebug(cgCtx, builder, 52, ptrToBuffer);

            // // Now offset into the buffer past the back pointer.
            // llvm::Value* skipBackPtr = builder.CreateConstGEP1_64(ptrToBuffer, sizeof(StringRef*));
            // assert (skipBackPtr->getType() == builder.getInt8PtrTy());
            // callDebug(cgCtx, builder, 53, skipBackPtr);

            // return skipBackPtr;
        }
    }

    ValuePair CGValue::getVarcharLengthAndData(CodegenContextImpl* cgCtx, llvm::IRBuilder<>& builder) const {
        VOLT_TRACE("Entering");
        if (isInlinedVarchar()) {
            return std::make_pair(getInlinedVarcharLength(builder, *this),
                                  getInlinedVarcharData(builder, *this));
        }

        assert(isOutlinedVarchar());
        llvm::Value* dataBuffer = getOutlinedVarcharBuffer(cgCtx, builder, *this);
        llvm::LLVMContext &ctx  = dataBuffer->getContext();

        // Now need to skip the length prefix.
        // The first byte describes how long the prefix is.
        llvm::IntegerType* int8Ty = llvm::Type::getInt8Ty(ctx);
        llvm::Value *firstByte = builder.CreateLoad(dataBuffer);
        llvm::Value *contBit = llvm::ConstantInt::get(int8Ty, OBJECT_CONTINUATION_BIT);
        llvm::Value *contBitIsSet = builder.CreateAnd(firstByte, contBit);
        contBitIsSet = builder.CreateICmpNE(contBitIsSet,
                                            builder.getInt8(0),
                                            "cont_bit");

        llvm::BasicBlock* currBlock = builder.GetInsertBlock();
        llvm::BasicBlock* merge = llvm::BasicBlock::Create(ctx, "merge", currBlock->getParent());
        merge->moveAfter(currBlock);

        llvm::BasicBlock* isLongData = llvm::BasicBlock::Create(ctx, "is_long_data", currBlock->getParent(), merge);
        llvm::BasicBlock* isShortData = llvm::BasicBlock::Create(ctx, "is_short_data", currBlock->getParent(), merge);

        builder.CreateCondBr(contBitIsSet, isLongData, isShortData);

        const char charMask = ~static_cast<char>(OBJECT_CONTINUATION_BIT | OBJECT_NULL_BIT);
        const uint32_t i32Mask = 0xffffff3f;
        VOLT_DEBUG("Here's the i32Mask: %d", i32Mask);
        builder.SetInsertPoint(isLongData);
        // load the 32-bit value
        llvm::Type* int32PtrTy = llvm::Type::getInt32PtrTy(ctx);
        llvm::Value* bufferInt32 = builder.CreateBitCast(dataBuffer, int32PtrTy);
        llvm::Value* longLength = builder.CreateLoad(bufferInt32);
        llvm::Value* wideMask = builder.getInt32(i32Mask);

        // zero-out the meta bits.
        longLength = builder.CreateAnd(longLength, wideMask);


        // llvm::Value* fourBytes = builder.CreateAlloca(builder.getInt8Ty(), builder.getInt8(4));
        // // populate the four bytes, swapping from original
        // for (int i = 0; i < 4; ++i) {
        //     llvm::Value* src = builder.CreateConstGEP1_32(dataBuffer, i);
        //     llvm::Value* byte = builder.CreateLoad(src);
        //     if (i == 0) {
        //         byte = builder.CreateAnd(byte, builder.getInt8(mask));
        //     }
        //     llvm::Value* dst = builder.CreateConstGEP1_32(fourBytes, 3 - i);
        //     builder.CreateStore(byte, dst);
        // }

        // VOLT_DEBUG("fourBytes type: %s", debugLlvm(fourBytes->getType()).c_str());
        // llvm::Value* longLengthPtr = builder.CreateBitCast(fourBytes, int32PtrTy);
        // llvm::Value* longLength = builder.CreateLoad(longLengthPtr);
        llvm::Function *bswapFn = llvm::Intrinsic::getDeclaration(cgCtx->getModule(),
                                                                  llvm::Intrinsic::bswap,
                                                                  std::vector<llvm::Type*>(1, builder.getInt32Ty()));
        assert(bswapFn != NULL);
        longLength = builder.CreateCall(bswapFn, longLength);
        longLength = builder.CreateZExt(longLength, getNativeSizeType(ctx));
        llvm::Value* longData = builder.CreateConstGEP1_32(dataBuffer, LONG_OBJECT_LENGTHLENGTH);
        builder.CreateBr(merge);

        builder.SetInsertPoint(isShortData);
        llvm::Value* shortLength = builder.CreateAnd(firstByte, builder.getInt8(charMask));
        shortLength = builder.CreateZExt(shortLength, getNativeSizeType(ctx));
        llvm::Value* shortData = builder.CreateConstGEP1_32(dataBuffer, SHORT_OBJECT_LENGTHLENGTH);
        builder.CreateBr(merge);

        builder.SetInsertPoint(merge);
        llvm::PHINode* len = builder.CreatePHI(getNativeSizeType(ctx), 2);
        len->addIncoming(longLength, isLongData);
        len->addIncoming(shortLength, isShortData);
        llvm::PHINode* data = builder.CreatePHI(builder.getInt8PtrTy(), 2);
        data->addIncoming(longData, isLongData);
        data->addIncoming(shortData, isShortData);

        return std::make_pair(len, data);
    }

    // Used by project node to do memcpy
    llvm::Value* CGValue::getInlinedVarcharTotalLength(llvm::IRBuilder<>& builder) const {
        assert(isInlinedVarchar());
        llvm::Value* dataLen = getInlinedVarcharLength(builder, *this);
        llvm::Value* shortLengthLength = llvm::ConstantInt::get(getNativeSizeType(dataLen->getContext()),
                                                                SHORT_OBJECT_LENGTHLENGTH);
        llvm::Value* totalLen = builder.CreateAdd(dataLen, shortLengthLength);
        return totalLen;
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
        VOLT_TRACE("Entering");
    }

    llvm::IRBuilder<>& ExprGenerator::builder() {
        return *m_builder;
    }

    llvm::Type* ExprGenerator::getLlvmType(const CGVoltType& cgVoltType) {
        if (cgVoltType.ty() == VALUE_TYPE_VARCHAR && cgVoltType.isInlined()) {
            // outlined strings currently not handled.
            return llvm::Type::getInt8Ty(m_codegenContext->getLlvmContext());
        }
        return m_codegenContext->getLlvmType(cgVoltType.ty());
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
        VOLT_TRACE("Entering");
        const NValue* paramValue = expr->getParamValue();
        // I have a theory that parameters and constants are never
        // marked as inlined, since there's no row to be associated
        // with them.  But is my theory true???
        assert(paramValue->getSourceInlined() == false);

        llvm::Constant* nvalueAddrAsInt = llvm::ConstantInt::get(getIntPtrType(),
                                                                 (uintptr_t)paramValue);

        // cast the pointer to the nvalue as a pointer to the value.
        // Since the first member of NValue is the 16-byte m_data
        // array, this is okay for all the numeric types.  But if
        // NValue ever changes, this code will break.
        llvm::PointerType* ptrTy = llvm::PointerType::getUnqual(getLlvmType(getExprType(expr)));
        llvm::Value* castedAddr = builder().CreateIntToPtr(nvalueAddrAsInt, ptrTy);

        std::ostringstream varName;
        varName << "param_" << expr->getValueIdx();
        return CGValue(builder().CreateLoad(castedAddr, varName.str().c_str()),
                       true, getExprType(expr)); // true means value may be null
    }

    CGValue
    ExprGenerator::codegenTupleValueExpr(const TupleSchema* schema,
                                         const TupleValueExpression* expr) {
        VOLT_TRACE("Entering");
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
        CGVoltType cgVoltType(getExprType(expr), columnInfo->inlined);
        if (cgVoltType.isInlinedVarchar()) {
            VOLT_TRACE("Exiting---inlined varchar");
            // just leave it as a pointer to char!
            return CGValue(addr, columnInfo->allowNull, cgVoltType);
        }
        else if (cgVoltType.isOutlinedVarchar()) {

            llvm::LLVMContext &ctx = addr->getContext();

            // cast addr (char*) to StringRef**, which we're modeling as char**.
            llvm::StructType* stringRefTy = getStringRefType(ctx);
            llvm::Type* ptrToStringRef = llvm::PointerType::getUnqual(stringRefTy);
            llvm::Type* ptrToPtrToStringRef = llvm::PointerType::getUnqual(ptrToStringRef);
            addr = builder().CreateBitCast(addr, ptrToPtrToStringRef);
            addr = builder().CreateLoad(addr);
            assert(addr->getType() == ptrToStringRef);

            VOLT_TRACE("Exiting---outlined varchar");
            return CGValue(addr, columnInfo->allowNull, cgVoltType);
        }

        llvm::Type* ptrTy = llvm::PointerType::getUnqual(getLlvmType(cgVoltType));
        llvm::Value* castedAddr = builder().CreateBitCast(addr,
                                                          ptrTy);
        std::ostringstream varName;
        varName << "field_" << expr->getColumnId();
            VOLT_TRACE("Exiting---numeric type");
        return CGValue(builder().CreateLoad(castedAddr, varName.str().c_str()),
                       columnInfo->allowNull, cgVoltType);
    }

    llvm::Function* ExprGenerator::getExtFn(const std::string& fnName) {
        //VOLT_DEBUG("Getting external function: %s", fnName.c_str());
        return m_codegenContext->getFunction(fnName);
    }

    llvm::Value*
    ExprGenerator::codegenCmpVarchar(ExpressionType exprType,
                                     const CGValue& lhs,
                                     const CGValue& rhs) {
        VOLT_TRACE("Entering");
        llvm::LLVMContext& ctx = lhs.val()->getContext();

        ValuePair lhsLenData = lhs.getVarcharLengthAndData(m_codegenContext, builder());
        ValuePair rhsLenData = rhs.getVarcharLengthAndData(m_codegenContext, builder());
        llvm::Value* lhsLen = lhsLenData.first;
        llvm::Value* rhsLen = rhsLenData.first;
        llvm::Value* lhsData = lhsLenData.second;
        llvm::Value* rhsData = rhsLenData.second;
        lhsLen->setName("vc_lhs_len");
        rhsLen->setName("vc_rhs_len");
        lhsData->setName("vc_lhs_data");
        rhsData->setName("vc_rhs_data");

        callDebugSize(m_codegenContext, builder(), 100, lhsLen);
        callDebugSize(m_codegenContext, builder(), 101, rhsLen);

        llvm::Value* lenDiff = builder().CreateSub(lhsLen, rhsLen, "len_diff");
        callDebugSize(m_codegenContext, builder(), 102, lenDiff);

        llvm::Value* lhsShorter = builder().CreateICmpSLT(lenDiff,
                                                          getZeroValue(lenDiff->getType()),
                                                          "lhs_shorter");
        llvm::Value* shorterLen = builder().CreateSelect(lhsShorter, lhsLen, rhsLen);
        assert (shorterLen->getType() == getNativeSizeType(ctx));
        // shorterLen = builder().CreateSExtOrBitCast(shorterLen,
        //                                            getNativeSizeType(ctx),
        //                                            "min_len");
        // now call strncmp(lhs, rhs, shorterLen);
        llvm::Value* strncmpResult = builder().CreateCall3(getExtFn("strncmp"),
                                                           lhsData,
                                                           rhsData,
                                                           shorterLen,
                                                           "strncmp_result");
        strncmpResult = builder().CreateSExt(strncmpResult, lenDiff->getType());

        callDebugSize(m_codegenContext, builder(), 103, strncmpResult);

        llvm::Value* zero = getZeroValue(strncmpResult->getType());
        llvm::Value* cmpResultIsZero = builder().CreateICmpEQ(strncmpResult,
                                                              zero,
                                                              "strncmp_result_zero");
        // If strncmpResult (strcmp's output) is zero, then the result of the comparison
        // is the length difference.
        VOLT_DEBUG("lenDiff type: %s", debugLlvm(lenDiff->getType()).c_str());
        VOLT_DEBUG("strncmpResult type: %s", debugLlvm(strncmpResult->getType()).c_str());

        llvm::Value* result = builder().CreateSelect(cmpResultIsZero,
                                                     lenDiff,
                                                     strncmpResult, "lex_order");
        VOLT_DEBUG("result type: %s", debugLlvm(result->getType()).c_str());
        callDebugSize(m_codegenContext, builder(), 104, result);

        // result now tells is whether lhs comes before rhs
        //   and is pos, zero, or neg

        // Now translate to true or false, based on the exprType
        llvm::Value* answer;
        switch (exprType) {
        case EXPRESSION_TYPE_COMPARE_EQUAL:
            answer =  builder().CreateICmpEQ(result, zero);
            break;
        case EXPRESSION_TYPE_COMPARE_NOTEQUAL:
            answer =  builder().CreateICmpNE(result, zero);
            break;
        case EXPRESSION_TYPE_COMPARE_LESSTHAN:
            answer =  builder().CreateICmpSLT(result, zero);
            break;
        case EXPRESSION_TYPE_COMPARE_GREATERTHAN:
            answer =  builder().CreateICmpSGT(result, zero);
            break;
        case EXPRESSION_TYPE_COMPARE_LESSTHANOREQUALTO:
            answer =  builder().CreateICmpSLE(result, zero);
            break;
        case EXPRESSION_TYPE_COMPARE_GREATERTHANOREQUALTO:
            answer =  builder().CreateICmpSGE(result, zero);
            break;
        default: {
            std::string msg = "varchar compare with op ";
            msg += expressionToString(exprType);
            throw UnsupportedForCodegenException(msg);
        }
        }

        // Widen the i1 to i8
        answer = builder().CreateZExt(answer, llvm::Type::getInt8Ty(ctx), "vc_cmp_result");
        return answer;
    }

    llvm::Value*
    ExprGenerator::codegenCmpOp(ExpressionType exprType,
                                ValueType outputType,
                                const CGValue& lhs,
                                const CGValue& rhs) {
        VOLT_TRACE("Entering");

        if (lhs.isVarchar()) {
            // find the shorter string.
            // invoke strncmp(lhs, rhs, shorterLen)
            // return comparison with return code
            return codegenCmpVarchar(exprType, lhs, rhs);
        }

        llvm::Value* lhsv = lhs.val();
        llvm::Value* rhsv = rhs.val();

        // For floating point types, we would CreateFCmp* here instead...
        llvm::Value* cmp = NULL;
        switch (exprType) {
        case EXPRESSION_TYPE_COMPARE_EQUAL:
            cmp = builder().CreateICmpEQ(lhsv, rhsv);
            break;
        case EXPRESSION_TYPE_COMPARE_NOTEQUAL:
            cmp = builder().CreateICmpNE(lhsv, rhsv);
            break;
        case EXPRESSION_TYPE_COMPARE_LESSTHAN:
            cmp = builder().CreateICmpSLT(lhsv, rhsv);
            break;
        case EXPRESSION_TYPE_COMPARE_GREATERTHAN:
            cmp = builder().CreateICmpSGT(lhsv, rhsv);
            break;
        case EXPRESSION_TYPE_COMPARE_LESSTHANOREQUALTO:
            cmp = builder().CreateICmpSLE(lhsv, rhsv);
            break;
        case EXPRESSION_TYPE_COMPARE_GREATERTHANOREQUALTO:
            cmp = builder().CreateICmpSGE(lhsv, rhsv);
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
    ExprGenerator::getZeroValue(llvm::Type* ty) {
        llvm::IntegerType* intTy = llvm::dyn_cast<llvm::IntegerType>(ty);
        return llvm::ConstantInt::get(intTy, 0);
    }

    // return an i1 that will be 1 if the expression is null.
    llvm::Value*
    ExprGenerator::compareToNull(const CGValue& cgVal) {
        // For floating point types, we would CreateFCmp* here instead...
        if (cgVal.isInlinedVarchar()) {
            VOLT_DEBUG("Generating null compare for inlined varchar");
            // Check the OBJECT_NULL_BIT in the first byte.
            llvm::Value* firstByte = builder().CreateLoad(cgVal.val());
            llvm::Value* andWithNullBit = builder().CreateAnd(firstByte, OBJECT_NULL_BIT);
            return builder().CreateICmpNE(andWithNullBit, getFalseValue(), "vc_is_null");
        }
        else if (cgVal.isOutlinedVarchar()) {
            VOLT_DEBUG("Generating null compare for outlined varchar");

            llvm::Value* asInt = builder().CreatePtrToInt(cgVal.val(), builder().getInt64Ty());
            return builder().CreateICmpEQ(asInt, builder().getInt64(0));

            // llvm::PointerType* pty = llvm::dyn_cast<llvm::PointerType>(cgVal.val()->getType());
            // return builder().CreateICmpNE(cgVal.val(),
            //                               llvm::ConstantPointerNull::get(pty));
        }
        else {
            return builder().CreateICmpEQ(cgVal.val(), getNullValueForType(cgVal.val()->getType()));
        }
    }

    llvm::BasicBlock*
    ExprGenerator::getEmptyBasicBlock(const std::string& label,
                                      llvm::BasicBlock* insertBefore) {
        return llvm::BasicBlock::Create(getLlvmContext(), label, m_function, insertBefore);
    }

    typedef std::pair<llvm::Value*, llvm::BasicBlock*> ValueBB;

    CGValue
    ExprGenerator::codegenConjunctionAndExpr(const TupleSchema* tupleSchema,
                                             const AbstractExpression* expr) {
        VOLT_TRACE("Entering");

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
        llvm::BasicBlock* resultBlock = getEmptyBasicBlock("and_result", NULL);
        resultBlock->moveAfter(builder().GetInsertBlock());
        CGValue left = codegenExpr(tupleSchema,
                                   expr->getLeft());
        llvm::BasicBlock *lhsFalseLabel = getEmptyBasicBlock("and_lhs_false", resultBlock);
        llvm::BasicBlock *lhsNotFalseLabel = getEmptyBasicBlock("and_lhs_not_false", resultBlock);
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
            llvm::BasicBlock *lhsTrueLabel = getEmptyBasicBlock("and_lhs_true", resultBlock);
            llvm::BasicBlock *lhsNullLabel = getEmptyBasicBlock("and_lhs_null", resultBlock);
            llvm::Value* lhsTrueCmp = builder().CreateICmpEQ(left.val(), getTrueValue());
            builder().CreateCondBr(lhsTrueCmp, lhsTrueLabel, lhsNullLabel);


            builder().SetInsertPoint(lhsTrueLabel);
            results.push_back(std::make_pair(right.val(), lhsTrueLabel));
            builder().CreateBr(resultBlock);

            // lhs is null

            builder().SetInsertPoint(lhsNullLabel);
            llvm::BasicBlock *rhsFalseLabel = getEmptyBasicBlock("and_rhs_false", resultBlock);
            llvm::BasicBlock *rhsNotFalseLabel = getEmptyBasicBlock("and_rhs_not_false", resultBlock);
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

        builder().SetInsertPoint(resultBlock);

        llvm::PHINode* phi = builder().CreatePHI(getLlvmType(getExprType(expr)), 3);

        std::vector<ValueBB>::iterator it = results.begin();
        for(; it != results.end(); ++it) {
            phi->addIncoming(it->first, it->second);
        }

        bool mayBeNull = left.mayBeNull() || right.mayBeNull();
        return CGValue(phi, mayBeNull, getExprType(expr));
    }

    // Sign-extend one side to the width of the wider side.
    // This will only work if lhs/rhs values are NOT NULL!
    std::pair<CGValue, CGValue> ExprGenerator::homogenizeTypes(const CGValue& lhs,
                                                               const CGValue& rhs) {
        VOLT_TRACE("Entering");
        if (lhs.isVarchar() != rhs.isVarchar()) {
            throw UnsupportedForCodegenException("Heterogenous compare with varchar");
        }
        else if (lhs.isVarchar()) {
            return std::make_pair(lhs, rhs);
        }

        llvm::IntegerType* lhsTy = llvm::dyn_cast<llvm::IntegerType>(lhs.val()->getType());
        llvm::IntegerType* rhsTy = llvm::dyn_cast<llvm::IntegerType>(rhs.val()->getType());

        if (lhsTy->getBitWidth() > rhsTy->getBitWidth()) {
            return std::make_pair(lhs,
                                  CGValue(builder().CreateSExt(rhs.val(), lhsTy),
                                          rhs.mayBeNull(),
                                          lhs.ty()));
        }
        else if (rhsTy->getBitWidth() > lhsTy->getBitWidth()) {
            return std::make_pair(CGValue(builder().CreateSExt(lhs.val(), rhsTy),
                                          lhs.mayBeNull(),
                                          rhs.ty()),
                                  rhs);
        }

        // types already homogenized.
        return std::make_pair(lhs, rhs);
    }

    CGValue
    ExprGenerator::codegenComparisonExpr(const TupleSchema* tupleSchema,
                                         const AbstractExpression* expr) {
        VOLT_TRACE("Entering");

        std::vector<ValueBB> results;
        llvm::BasicBlock* resultBlock = getEmptyBasicBlock("cmp_result", NULL);
        resultBlock->moveAfter(builder().GetInsertBlock());
        CGValue left = codegenExpr(tupleSchema,
                                   expr->getLeft());
        if (left.mayBeNull()) { // value produced on LHS may be null
            llvm::BasicBlock* lhsIsNull = getEmptyBasicBlock("cmp_lhs_null", resultBlock);
            llvm::BasicBlock* lhsNotNull = getEmptyBasicBlock("cmp_lhs_not_null", resultBlock);

            llvm::Value* cmp = compareToNull(left);
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
            llvm::BasicBlock* rhsIsNull = getEmptyBasicBlock("cmp_rhs_null", resultBlock);
            llvm::BasicBlock* rhsNotNull = getEmptyBasicBlock("cmp_rhs_not_null", resultBlock);
            llvm::Value* cmp = compareToNull(right);
            builder().CreateCondBr(cmp, rhsIsNull, rhsNotNull);

            builder().SetInsertPoint(rhsIsNull);
            results.push_back(std::make_pair(getNullValueForType(getLlvmType(VALUE_TYPE_BOOLEAN)),
                                             rhsIsNull));
            builder().CreateBr(resultBlock);

            builder().SetInsertPoint(rhsNotNull);
        }

        // Types on both sides may not be the same.
        std::pair<CGValue, CGValue> lhsRhs = homogenizeTypes(left, right);

        llvm::Value* cmp = codegenCmpOp(expr->getExpressionType(),
                                        getExprType(expr),
                                        lhsRhs.first,
                                        lhsRhs.second);
        results.push_back(std::make_pair(cmp, builder().GetInsertBlock()));
        builder().CreateBr(resultBlock);

        builder().SetInsertPoint(resultBlock);
        llvm::PHINode* phi = builder().CreatePHI(getLlvmType(getExprType(expr)), 3);

        std::vector<ValueBB>::iterator it = results.begin();
        for(; it != results.end(); ++it) {
            phi->addIncoming(it->first, it->second);
        }

        bool mayBeNull = left.mayBeNull() || right.mayBeNull();
        return CGValue(phi, mayBeNull, getExprType(expr));
    }

    CGValue
    ExprGenerator::codegenIsNullExpr(const TupleSchema* tupleSchema,
                                     const OperatorIsNullExpression* expr) {
        VOLT_TRACE("Entering");
        CGValue child = codegenExpr(tupleSchema,
                                    expr->getLeft());
        if (! child.mayBeNull()) {
            // argument is never null, is isNull is always false here.
            return CGValue(getFalseValue(), false, VALUE_TYPE_BOOLEAN);
        }

        llvm::Value* cmp = compareToNull(child);
        return CGValue(builder().CreateZExt(cmp, getLlvmType(VALUE_TYPE_BOOLEAN)),
                       false, VALUE_TYPE_BOOLEAN); // result will never be null
    }

    CGValue
    ExprGenerator::codegenConstantValueExpr(const TupleSchema*,
                                            const ConstantValueExpression* expr) {
        VOLT_TRACE("Entering");
        // constant value should never need to access tuples,
        // so it should be ok to just pass nulls here.
        NValue nval = expr->eval(NULL, NULL);
        assert(nval.getSourceInlined() == false);

        ValueType vt = ValuePeeker::peekValueType(nval);
        llvm::Type* ty = getLlvmType(vt);
        if (nval.isNull()) {
            return CGValue(getNullValueForType(ty),
                           true, vt);
        }

        llvm::Value* k = llvm::ConstantInt::get(ty,
                                                ValuePeeker::peekAsBigInt(nval));
        return CGValue(k, false, vt); // never null if we get here.
    }

    CGValue
    ExprGenerator::codegenExpr(const TupleSchema* tupleSchema,
                               const AbstractExpression* expr) {
        VOLT_TRACE("Entering");
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
