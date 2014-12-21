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
#include "llvm/Support/raw_ostream.h"

#include <map>
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
class StructType;
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

        // returns an llvm integer type that can store a pointer on
        // the jit's target
        llvm::IntegerType* getIntPtrType();

        llvm::Value* getColumnOffset(const TupleSchema* schema, int columnId);

        llvm::Function* getFunction(const std::string& fnName);

        void registerExternalTy(const std::string& typeName);

        ~CodegenContextImpl();

        static void shutdownLlvm();

    private:

        void* generateCode(llvm::Function* fn);

        boost::scoped_ptr<llvm::LLVMContext> m_llvmContext;
        llvm::Module* m_module;
        boost::scoped_ptr<llvm::ExecutionEngine> m_executionEngine;
        boost::scoped_ptr<llvm::legacy::FunctionPassManager> m_passManager;

        std::string m_errorString;

        std::map<std::string, llvm::StructType*> m_externalTypesMap;
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

    // This should not really be necessary, but sometimes the NValue
    // produced by an expression's eval() method does not match the
    // ValueType produced by calling expr->getValueType().  This
    // function is provided to work around this.
    ValueType getExprType(const AbstractExpression* expr);

    llvm::IntegerType* getNativeSizeType(llvm::LLVMContext& ctx);
    llvm::StructType* getStringRefType(llvm::LLVMContext &ctx);
    llvm::PointerType* getPtrToStringRefType(llvm::LLVMContext &ctx);
    llvm::PointerType* getPtrToPtrToStringRefType(llvm::LLVMContext &ctx);
    llvm::StructType* getTableTupleType(llvm::LLVMContext &ctx);

    // Works with llvm::Value and llvm::Type
    template<typename T>
    std::string debugLlvm(T* v) {
        std::string irDump;
        llvm::raw_string_ostream rso(irDump);
        v->print(rso);
        return irDump;
    }
}

#endif
