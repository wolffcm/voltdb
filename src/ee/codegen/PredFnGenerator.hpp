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

#include <string>
#include "common/types.h"

#include "llvm/IR/IRBuilder.h"
#include "boost/scoped_ptr.hpp"

namespace llvm {
    class Function;
    class LLVMContext;
    class Value;
}

namespace voltdb {

    class CodegenContextImpl;
    class TupleSchema;
    class AbstractExpression;

    // maintains the current state of the LLVM function being generated
    class PredFnGenerator {
    public:
        // Create a function context for a function that
        //   accepts a pointer to a tuple
        //   returns a boolean
        //   has external linkage (can be called from outside llvm module)
        PredFnGenerator(CodegenContextImpl* codegenContext, const std::string& name);

        void codegen(const TupleSchema* tupleSchema,
                     const AbstractExpression* expr);

        llvm::Function* getFunction();

    private:

        void init(const std::string& name,
                  ValueType returnTy);

        llvm::Value* getTupleArg();

        llvm::IRBuilder<>& builder();

        llvm::Type* getLlvmType(ValueType voltType);

        llvm::LLVMContext& getLlvmContext();

        CodegenContextImpl* m_codegenContext;
        llvm::Function* m_function;
        boost::scoped_ptr<llvm::IRBuilder<> > m_builder;
    };
}
