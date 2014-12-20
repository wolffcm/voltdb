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

#ifndef _EXPRGENERATOR_HPP_
#define _EXPRGENERATOR_HPP_

#include "llvm/IR/IRBuilder.h"

#include "common/types.h"

namespace voltdb {

    class AbstractExpression;
    class OperatorIsNullExpression;
    class ConstantValueExpression;
    class CodegenContextImpl;
    class TupleSchema;
    class TupleValueExpression;
    class ParameterValueExpression;

    class CGVoltType {
    public:
        CGVoltType(ValueType valueType, bool isInlined)
            : m_valueType(valueType)
            , m_isInlined(isInlined)
        {
        }

        // not explicit
        CGVoltType(ValueType vt)
            : m_valueType(vt)
            , m_isInlined(false)
        {
        }

        ValueType ty() const {
            return m_valueType;
        }

        bool isInlined() const {
            return m_isInlined;
        }

        bool isInlinedVarchar() const {
            return ty() == VALUE_TYPE_VARCHAR && isInlined();
        }

        bool isOutlinedVarchar() const {
            return ty() == VALUE_TYPE_VARCHAR && !isInlined();
        }

    private:
        ValueType m_valueType;
        bool m_isInlined;
    };

    typedef std::pair<llvm::Value*, llvm::Value*> ValuePair;
    // Bundles an llvm::Value* with may-be-null meta-data,
    // as well as the value type and inlined info.
    class CGValue {
    public:
        CGValue(llvm::Value* val, bool mayBeNull, const CGVoltType& cgVoltType)
            : m_value(val)
            , m_mayBeNull(mayBeNull)
            , m_cgVoltType(cgVoltType)
        {
        }

        llvm::Value* val() const {
            return m_value;
        }

        bool mayBeNull() const {
            return m_mayBeNull;
        }

        ValueType ty() const {
            return m_cgVoltType.ty();
        }

        bool isInlined() const {
            return m_cgVoltType.isInlined();
        }

        bool isInlinedVarchar() const {
            return m_cgVoltType.isInlinedVarchar();
        }

        bool isOutlinedVarchar() const {
            return m_cgVoltType.isOutlinedVarchar();
        }

        bool isVarchar() const {
            return ty() == VALUE_TYPE_VARCHAR;
        }

        llvm::Value* getInlinedVarcharTotalLength(llvm::IRBuilder<>& builder) const;

        ValuePair getVarcharLengthAndData(CodegenContextImpl *cgCtx,
                                          llvm::IRBuilder<>& builder) const;


    private:
        llvm::Value* m_value;
        bool m_mayBeNull;
        CGVoltType m_cgVoltType;
    };

    class ExprGenerator {
    public:
        ExprGenerator(CodegenContextImpl* codegenContext,
                      llvm::Function* function,
                      llvm::IRBuilder<>* builder,
                      llvm::Value* tupleArg);

        CGValue
        codegenExpr(const TupleSchema* tupleSchema,
                    const AbstractExpression* expr);

        static llvm::Type* getLlvmType(llvm::LLVMContext& ctx,
                                       const CGVoltType& voltType);
    private:

        llvm::IRBuilder<>& builder();
        llvm::LLVMContext& getLlvmContext();
        llvm::Type* getIntPtrType();
        llvm::Value* getTupleArg();
        llvm::Value* getTrueValue();
        llvm::Value* getFalseValue();
        llvm::Value* getZeroValue(llvm::Type* ty);
        llvm::Value* compareToNull(const CGValue& cgVal);

        llvm::BasicBlock* getEmptyBasicBlock(const std::string& label,
                                             llvm::BasicBlock* insertBefore);

        std::pair<CGValue, CGValue> homogenizeTypes(const CGValue& lhs,
                                                    const CGValue& rhs);


        CGValue
        codegenParameterValueExpr(const TupleSchema*,
                                  const ParameterValueExpression* expr);
        CGValue
        codegenTupleValueExpr(const TupleSchema* schema,
                              const TupleValueExpression* expr);
        llvm::Value*
        codegenCmpVarchar(ExpressionType exprType,
                          const CGValue& lhs,
                          const CGValue& rhs);

        llvm::Value*
        codegenCmpOp(ExpressionType exprType,
                     ValueType outputType,
                     const CGValue& lhs,
                     const CGValue& rhs);


        CGValue
        codegenConjunctionAndExpr(const TupleSchema* tupleSchema,
                                  const AbstractExpression* expr);

        CGValue
        codegenComparisonExpr(const TupleSchema* tupleSchema,
                              const AbstractExpression* expr);
        CGValue
        codegenIsNullExpr(const TupleSchema* tupleSchema,
                          const OperatorIsNullExpression* expr);


        CGValue
        codegenConstantValueExpr(const TupleSchema*,
                                 const ConstantValueExpression* expr);

        llvm::Function* getExtFn(const std::string& fnName);


        CodegenContextImpl* m_codegenContext;
        llvm::Function* m_function;
        llvm::IRBuilder<>* m_builder;
        llvm::Value* m_tupleArg;

    };

}

#endif
