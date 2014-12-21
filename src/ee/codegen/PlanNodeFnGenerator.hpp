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

#include "llvm/IR/IRBuilder.h"
#include "boost/scoped_ptr.hpp"

namespace llvm {
    class Function;
    class LLVMContext;
    class Value;
}

namespace voltdb {

    class AbstractExecutor;
    class AbstractExpression;
    class AbstractPlanNode;
    class CodegenContextImpl;
    class CGValue;
    class ProjectionPlanNode;
    class SeqScanPlanNode;
    class IndexScanPlanNode;
    class TupleSchema;

    class PlanNodeFnGenerator {
    public:
        PlanNodeFnGenerator(CodegenContextImpl* codegenContext,
                      AbstractExecutor* executor);

        void init(AbstractPlanNode *node);
        void codegen(AbstractPlanNode *node);
        llvm::Function* getFunction() const;

        static void addExternalPrototypes(llvm::Module* module);

    private:
        llvm::Value* getInputTable();
        llvm::Value* getOutputTable();
        static bool isTrivialScan(SeqScanPlanNode* n);
        llvm::Function* getExtFn(const std::string& fnName);

        // A value that points to a TableTuple object.  return a
        // pointer to its backing storage.
        llvm::Value* getTupleStorage(llvm::Value* tuple,
                                     const std::string& name);

        // Given a reference to a table tuple, return the address of the
        // pointer to the schema
        llvm::Value* getTableTupleSchemaAddress(llvm::Value* tableTuple);

        void storeInTuple(llvm::Value* addressInTupleStorage,
                          const CGValue& cgVal);

        void codegenProjectionInline(ProjectionPlanNode* node,
                                     const TupleSchema* inputSchema,
                                     llvm::Value* inputTupleStorage,
                                     const TupleSchema* outputSchema,
                                     llvm::Value* outputTupleStorage);

        llvm::Value* codegenSeqScanPredicate(AbstractExpression* pred,
                                             const TupleSchema* schema,
                                             llvm::Value* tupleStorage);

        void codegenSeqScan(SeqScanPlanNode* node);
        void codegenIndexScan(IndexScanPlanNode* node);
        llvm::LLVMContext& getLlvmContext();

        llvm::IRBuilder<>& builder();

        CodegenContextImpl* m_codegenContext;
        llvm::Function* m_function;
        boost::scoped_ptr<llvm::IRBuilder<> > m_builder;
    };
}
