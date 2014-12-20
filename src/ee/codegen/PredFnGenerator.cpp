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
#include "codegen/CodegenContextImpl.hpp"
#include "codegen/PredFnGenerator.hpp"
#include "codegen/ExprGenerator.hpp"
#include "llvm/IR/Function.h"

namespace voltdb {

    // Create a function context for a function that
    //   accepts a pointer to a tuple
    //   returns a boolean
    //   has external linkage (can be called from outside llvm module)
    PredFnGenerator::PredFnGenerator(CodegenContextImpl* codegenContext, const std::string& name)
        : m_codegenContext(codegenContext)
        , m_function(NULL)
        , m_builder()
    {
        init(name, VALUE_TYPE_BOOLEAN);
    }

    void PredFnGenerator::codegen(const TupleSchema* tupleSchema,
                                  const AbstractExpression* expr) {
        ExprGenerator generator(m_codegenContext, m_function, m_builder.get(), getTupleArg());
        llvm::Value* answer = generator.codegenExpr(tupleSchema, expr).val();
        builder().CreateRet(answer);
    }

    llvm::Function* PredFnGenerator::getFunction() {
        return m_function;
    }

    void PredFnGenerator::init(const std::string& name,
                               ValueType returnTy) {
        llvm::LLVMContext &ctx = getLlvmContext();

        std::vector<llvm::Type*> argType(1, llvm::Type::getInt8PtrTy(ctx));
        llvm::Type* retType = getLlvmType(returnTy);
        llvm::FunctionType* ft = llvm::FunctionType::get(retType, argType, false);
        m_function = llvm::Function::Create(ft,
                                            llvm::Function::ExternalLinkage,
                                            name,
                                            m_codegenContext->getModule());

        m_function->arg_begin()->setName("tuple");

        llvm::BasicBlock *bb = llvm::BasicBlock::Create(ctx, "entry", m_function);
        m_builder.reset(new llvm::IRBuilder<>(bb));
    }

    llvm::Value* PredFnGenerator::getTupleArg() {
        return m_function->arg_begin();
    }

    llvm::LLVMContext& PredFnGenerator::getLlvmContext() {
        return m_codegenContext->getLlvmContext();
    }


    llvm::IRBuilder<>& PredFnGenerator::builder() {
        return *m_builder;
    }

    llvm::Type* PredFnGenerator::getLlvmType(ValueType voltType) {
        return m_codegenContext->getLlvmType(voltType);
    }
}
