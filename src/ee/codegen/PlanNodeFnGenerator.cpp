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

#include "codegen/PlanNodeFnGenerator.hpp"
#include "codegen/ExprGenerator.hpp"
#include "codegen/CodegenContextImpl.hpp"
#include "common/debuglog.h"
#include "plannodes/seqscannode.h"
#include "plannodes/projectionnode.h"
#include "storage/table.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/Value.h"

namespace voltdb {

    PlanNodeFnGenerator::PlanNodeFnGenerator(CodegenContextImpl* codegenContext, AbstractExecutor* executor)
        : m_codegenContext(codegenContext)
        , m_function(NULL)
        , m_builder()
    {
    }

    void PlanNodeFnGenerator::init(AbstractPlanNode *node) {
        llvm::LLVMContext &ctx = getLlvmContext();

        // Function prototype for a plan node looks like
        //
        // bool
        // planNodeFunction(Table* inTable, Table* outTable);
        //
        // represent the tables as void* for now.

        std::ostringstream name;
        name << planNodeToString(node->getPlanNodeType()) << "_"
             << node->getPlanNodeId() << "_execute";

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

    void PlanNodeFnGenerator::codegen(AbstractPlanNode *node) {
        PlanNodeType pnt = node->getPlanNodeType();
        switch (pnt) {
        case PLAN_NODE_TYPE_SEQSCAN:
            codegenSeqScan(static_cast<SeqScanPlanNode*>(node));
            break;
        default: {
            std::ostringstream oss;
            oss << "node type " << planNodeToString(pnt);
            throw UnsupportedForCodegenException(oss.str());
        }
        }
    }

    llvm::Function* PlanNodeFnGenerator::getFunction() const {
        return m_function;
    }

    llvm::Value* PlanNodeFnGenerator::getInputTable() {
        return m_function->arg_begin();
    }

    llvm::Value* PlanNodeFnGenerator::getOutputTable() {
        return ++(m_function->arg_begin());
    }

    bool PlanNodeFnGenerator::isTrivialScan(SeqScanPlanNode* n) {
        if (n->getPredicate() != NULL) {
            //VOLT_DEBUG("Scan is not trivial: has predicate");
            return false;
        }

        if (n->getInlinePlanNodes().size() > 0) {
            return false;
        }

        return true;
    }

    llvm::Function* PlanNodeFnGenerator::getExtFn(const std::string& fnName) {
        //VOLT_DEBUG("Getting external function: %s", fnName.c_str());
        return m_codegenContext->getFunction(fnName);
    }

    // A value that points to a TableTuple object.  return a
    // pointer to its backing storage.
    llvm::Value* PlanNodeFnGenerator::getTupleStorage(llvm::Value* tuple, const std::string& name) {
        assert(tuple->getType() == llvm::PointerType::getUnqual(getTableTupleType(tuple->getContext())));

        llvm::Value* storage = builder().CreateConstGEP2_32(tuple, 0, 1);
        storage = builder().CreateLoad(storage, name);

        assert(storage->getType() == llvm::Type::getInt8PtrTy(tuple->getContext()));
        return storage;
    }

    // Given a reference to a table tuple, return the address of the
    // pointer to the schema
    llvm::Value* PlanNodeFnGenerator::getTableTupleSchemaAddress(llvm::Value* tableTuple) {
        assert(tableTuple->getType() == llvm::PointerType::getUnqual(getTableTupleType(tableTuple->getContext())));
        return builder().CreateConstGEP2_32(tableTuple, 0, 0);
    }


    void PlanNodeFnGenerator::storeInTuple(llvm::Value* addressInTupleStorage, const CGValue& cgVal) {
        VOLT_TRACE("Entering");
        llvm::LLVMContext& ctx = cgVal.val()->getContext();
        if (cgVal.isInlinedVarchar()) {
            // Use memcpy
            llvm::Function* memcpyFn = getExtFn("memcpy");
            builder().CreateCall3(memcpyFn,
                                  addressInTupleStorage,
                                  cgVal.val(),
                                  cgVal.getInlinedVarcharTotalLength(builder()));
        }
        else {
            llvm::Type* elemTy = ExprGenerator::getLlvmType(ctx, cgVal.ty());
            llvm::Type* ptrTy = llvm::PointerType::getUnqual(elemTy);
            llvm::Value* castedAddr = builder().CreateBitCast(addressInTupleStorage, ptrTy);
            builder().CreateStore(cgVal.val(), castedAddr);
        }
    }


    void PlanNodeFnGenerator::codegenProjectionInline(ProjectionPlanNode* node,
                                                      const TupleSchema* inputSchema,
                                                      llvm::Value* inputTupleStorage,
                                                      const TupleSchema* outputSchema,
                                                      llvm::Value* outputTupleStorage) {
        const std::vector<AbstractExpression*>& projectedExprs =
            node->getOutputColumnExpressions();


        for (int i = 0; i < projectedExprs.size(); ++i) {
            AbstractExpression* expr = projectedExprs[i];
            ExprGenerator generator(m_codegenContext,
                                    getFunction(),
                                    m_builder.get(), inputTupleStorage);
            CGValue cgv = generator.codegenExpr(inputSchema, expr);
            VOLT_TRACE("Projected expression %d generated", i);
            // place the computed expression in the output tuple
            // Find the offset of the ith column
            llvm::Value* offset = m_codegenContext->getColumnOffset(outputSchema, i);
            llvm::Value* address = builder().CreateGEP(outputTupleStorage, offset);
            storeInTuple(address, cgv);

        }
    }

    llvm::Value* PlanNodeFnGenerator::codegenSeqScanPredicate(AbstractExpression* pred,
                                                              const TupleSchema* schema,
                                                              llvm::Value* tupleStorage) {
        llvm::LLVMContext &ctx = getLlvmContext();
        ExprGenerator generator(m_codegenContext, getFunction(), m_builder.get(), tupleStorage);
        llvm::Value* v = generator.codegenExpr(schema, pred).val();
        llvm::Value *one = llvm::ConstantInt::get(llvm::Type::getInt8Ty(ctx), 1);
        llvm::Value* cmpResult = builder().CreateICmpEQ(v, one, "pred_result");
        return cmpResult;
    }


    void PlanNodeFnGenerator::codegenSeqScan(SeqScanPlanNode* node) {
        llvm::LLVMContext &ctx = getLlvmContext();

        if (isTrivialScan(node)) {
            VOLT_TRACE("Creating trivial function for scan which does nothing");
            llvm::Value* retValue = llvm::ConstantInt::get(llvm::Type::getInt8Ty(ctx), 1);
            builder().CreateRet(retValue);
            return;
        }

        ProjectionPlanNode* projNode = static_cast<ProjectionPlanNode*>(node->getInlinePlanNode(PLAN_NODE_TYPE_PROJECTION));
        std::map<PlanNodeType, AbstractPlanNode*>::size_type numInlinedNodes = node->getInlinePlanNodes().size();
        if (numInlinedNodes > 1 || (projNode == NULL && numInlinedNodes > 0)) {
            throw UnsupportedForCodegenException("limit or agg inlined in scan");
        }

        Table* inputTable = (node->isSubQuery()) ?
            node->getChildren()[0]->getOutputTable():
            node->getTargetTable();
        Table* outputTable = node->getOutputTable();

        assert(inputTable != NULL);
        assert(outputTable != NULL);

        llvm::BasicBlock *scanLoopExit = llvm::BasicBlock::Create(getLlvmContext(),
                                                                  "scan_loop_exit",
                                                                  getFunction());
        llvm::BasicBlock *scanLoopEntry = llvm::BasicBlock::Create(getLlvmContext(),
                                                                   "scan_loop_entry",
                                                                   getFunction(),
                                                                   scanLoopExit);
        llvm::BasicBlock *scanLoopBody = llvm::BasicBlock::Create(getLlvmContext(),
                                                                  "scan_loop_body",
                                                                  getFunction(),
                                                                  scanLoopExit);

        // Allocate space for the TableTuple structure on the stack.
        // We need to pass a reference to the iterator, and we don't
        // want to overwrite the input table's temp tuple.
        llvm::Value* inputTuple = builder().CreateAlloca(getTableTupleType(ctx));
        llvm::Value* inputSchema = builder().CreateCall(getExtFn("table_schema"),
                                                        getInputTable(), "input_schema");
        // Need to store a pointer to the schema in the tuple, to pass the
        // iterator's sanity checks.  In general any access to TupleSchema should be
        // unnecessary at run time, but being expedient for now.
        builder().CreateStore(inputSchema, getTableTupleSchemaAddress(inputTuple));
        llvm::Value* outputTuple = inputTuple;
        llvm::Value* outputTupleStorage = NULL;
        if (projNode != NULL) {
            llvm::Function* tableTempTupleFn = getExtFn("table_temp_tuple");
            outputTuple = builder().CreateCall(tableTempTupleFn,
                                               getOutputTable(),
                                               "output_tuple");

            // Get the address of the storage for the output tuple
            outputTupleStorage = getTupleStorage(outputTuple, "output_tuple_storage");

        }
        llvm::Function* getIterFn = getExtFn("table_get_iterator");
        llvm::Value* inputIter = builder().CreateCall(getIterFn,
                                                      getInputTable(),
                                                      "input_table_iter");
        builder().CreateBr(scanLoopEntry);

        // The test of the loop condition
        builder().SetInsertPoint(scanLoopEntry);
        llvm::Function* iterGetNextFn = getExtFn("iterator_next");
        llvm::Value* found = builder().CreateCall2(iterGetNextFn,
                                                   inputIter, inputTuple);
        llvm::Value *zero = llvm::ConstantInt::get(llvm::Type::getInt8Ty(ctx), 0);
        llvm::Value* cmpResult = builder().CreateICmpNE(found, zero, "tuple_found");
        builder().CreateCondBr(cmpResult, scanLoopBody, scanLoopExit);

        // We have an input row.  Process it.
        builder().SetInsertPoint(scanLoopBody);
        llvm::Value* inputTupleStorage = getTupleStorage(inputTuple, "input_tuple_storage");
        if (node->getPredicate()) {
            llvm::BasicBlock *predPassed = llvm::BasicBlock::Create(getLlvmContext(),
                                                                    "pred_passed",
                                                                    getFunction(),
                                                                    scanLoopExit);

            llvm::Value* predResult = codegenSeqScanPredicate(node->getPredicate(), inputTable->schema(), inputTupleStorage);
            builder().CreateCondBr(predResult, predPassed, scanLoopEntry);
            builder().SetInsertPoint(predPassed);
        }

        if (projNode != NULL) {
            VOLT_TRACE("Generating projection");
            codegenProjectionInline(projNode,
                                    inputTable->schema(),
                                    inputTupleStorage,
                                    outputTable->schema(),
                                    outputTupleStorage);
            VOLT_TRACE("Projection complete");
        }
        llvm::Function* insertTupleFn =
            getExtFn("table_insert_tuple_nonvirtual");
        // args.clear();
        // args.push_back(getOutputTable());
        // args.push_back(outputTuple);
        builder().CreateCall2(insertTupleFn, getOutputTable(), outputTuple);
        builder().CreateBr(scanLoopEntry);

        // No more rows.
        builder().SetInsertPoint(scanLoopExit);
        llvm::Value* retValue = llvm::ConstantInt::get(llvm::Type::getInt8Ty(ctx), 1);
        builder().CreateRet(retValue);
    }

    llvm::LLVMContext& PlanNodeFnGenerator::getLlvmContext() {
        return m_codegenContext->getLlvmContext();
    }

    llvm::IRBuilder<>& PlanNodeFnGenerator::builder() {
        return *m_builder;
    }
}
