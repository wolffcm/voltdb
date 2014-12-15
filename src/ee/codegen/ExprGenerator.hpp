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

    namespace {
        class CGValue;
    }

    class ExprGenerator {
    public:
        ExprGenerator(CodegenContextImpl* codegenContext,
                      llvm::Function* function,
                      llvm::IRBuilder<>* builder,
                      llvm::Value* tupleArg);

        llvm::Value* generate(const TupleSchema* schema, const AbstractExpression* expr);

    private:

        llvm::IRBuilder<>& builder();
        llvm::LLVMContext& getLlvmContext();
        llvm::Type* getLlvmType(ValueType voltType);
        llvm::Type* getIntPtrType();
        llvm::Value* getTupleArg();
        llvm::Value* getTrueValue();
        llvm::Value* getFalseValue();
        llvm::Value* compareToNull(llvm::Value* val);

        llvm::BasicBlock* getEmptyBasicBlock(const std::string& label);

        std::pair<llvm::Value*, llvm::Value*> homogenizeTypes(llvm::Value* lhs,
                                                              llvm::Value* rhs);


        CGValue
        codegenParameterValueExpr(const TupleSchema*,
                                  const ParameterValueExpression* expr);
        CGValue
        codegenTupleValueExpr(const TupleSchema* schema,
                              const TupleValueExpression* expr);
        llvm::Value*
        codegenCmpOp(ExpressionType exprType,
                     ValueType outputType,
                     llvm::Value* lhs,
                     llvm::Value* rhs);
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

        CGValue
        codegenExpr(const TupleSchema* tupleSchema,
                    const AbstractExpression* expr);



        CodegenContextImpl* m_codegenContext;
        llvm::Function* m_function;
        llvm::IRBuilder<>* m_builder;
        llvm::Value* m_tupleArg;

    };

}

#endif
