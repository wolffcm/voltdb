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

#ifndef _CODEGENCONTEXTIMPL_HPP_
#define _CODEGENCONTEXTIMPL_HPP_

#include "boost/scoped_ptr.hpp"
#include "common/types.h"

#include "llvm/IR/IRBuilder.h"

#include <string>
#include <sstream>

namespace llvm {
class ExecutionEngine;
    namespace legacy {
class FunctionPassManager;
    }
class LLVMContext;
class Module;
class Value;
class Type;
class IntegerType;
}

namespace voltdb {

    class AbstractExecutor;
    class AbstractExpression;
    class TupleSchema;

    class CodegenContextImpl {
    public:
        CodegenContextImpl();

        PredFunction compilePredicate(const std::string& fnName,
                                      const TupleSchema* tupleSchema,
                                      const AbstractExpression* expr);

        PlanNodeFunction compilePlanNode(AbstractExecutor* executor);

        llvm::Module* getModule();
        llvm::LLVMContext& getLlvmContext();

        llvm::Type* getLlvmType(ValueType voltType);

        // returns an llvm integer type that can store a pointer on the jit's target
        llvm::IntegerType* getIntPtrType();

        ~CodegenContextImpl();

        static void shutdownLlvm();

    private:

        void* generateCode(llvm::Function* fn);

        boost::scoped_ptr<llvm::LLVMContext> m_llvmContext;
        llvm::Module* m_module;
        boost::scoped_ptr<llvm::ExecutionEngine> m_executionEngine;
        boost::scoped_ptr<llvm::legacy::FunctionPassManager> m_passManager;

        std::string m_errorString;
   };

    // This is thrown if we encounter something we can't yet generate
    // code for.  In this case, we can always fall back to
    // interpreting the expression.
    class UnsupportedForCodegenException {
    public:
        UnsupportedForCodegenException(const std::string& message)
            : m_message(message)
        {}

        std::string getMessage() const {
            std::ostringstream oss;
            oss << "Unsupported for codegen: " << m_message;
            return oss.str();
        }

    private:
        const std::string m_message;
    };
}

#endif
