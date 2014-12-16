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
#include "plannodes/seqscannode.h"
#include "plannodes/projectionnode.h"

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

    namespace {

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

            llvm::Value* getTupleArg() {
                return m_function->arg_begin();
            }

            llvm::LLVMContext& getLlvmContext() {
                return m_codegenContext->getLlvmContext();
            }


            llvm::IRBuilder<>& builder() {
                return *m_builder;
            }

            llvm::Type* getLlvmType(ValueType voltType) {
                return m_codegenContext->getLlvmType(voltType);
            }

            CodegenContextImpl* m_codegenContext;
            llvm::Function* m_function;
            boost::scoped_ptr<llvm::IRBuilder<> > m_builder;
        };

    }}

extern "C" {
    // These are C wrappers for functions called from
    // generated code

    voltdb::TableIterator* table_get_iterator(voltdb::Table* table) {
        return &(table->iteratorDeletingAsWeGo());
    }

    voltdb::TableTuple* table_temp_tuple(voltdb::Table* table) {
        return &(table->tempTuple());
    }

    void table_insert_tuple_nonvirtual(voltdb::TempTable* table, voltdb::TableTuple* tuple) {
        table->insertTupleNonVirtual(*tuple);
    }

    bool iterator_next(voltdb::TableIterator* iterator, voltdb::TableTuple* tuple) {
        return iterator->next(*tuple);
    }

    char* tuple_address(voltdb::TableTuple* tuple) {
        return tuple->address();
    }
}

namespace voltdb { namespace {

        class PlanNodeFnCtx {
        public:
            PlanNodeFnCtx(CodegenContextImpl* codegenContext, AbstractExecutor* executor)
                : m_codegenContext(codegenContext)
                , m_function(NULL)
                , m_builder()
            {
            }

            void init(AbstractPlanNode *node) {
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

            void codegen(AbstractPlanNode *node) {
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

            llvm::Function* getFunction() const {
                return m_function;
            }

        private:
            llvm::Value* getInputTable() {
                return m_function->arg_begin();
            }

            llvm::Value* getOutputTable() {
                return ++(m_function->arg_begin());
            }

            static bool isTrivialScan(SeqScanPlanNode* n) {
                if (n->getPredicate() != NULL) {
                    VOLT_DEBUG("Scan is not trivial: has predicate");
                    return false;
                }

                if (n->getInlinePlanNodes().size() > 0) {
                    VOLT_DEBUG("Scan is not trivial: found inlined nodes");
                    typedef std::map<PlanNodeType, AbstractPlanNode*> InlineMap;
                    const InlineMap& inlineNodes = n->getInlinePlanNodes();
                    InlineMap::const_iterator end = inlineNodes.end();
                    for (InlineMap::const_iterator it = inlineNodes.begin(); it != end; ++it) {
                        VOLT_DEBUG("  %s", planNodeToString(it->first).c_str());
                    }
                    return false;
                }

                return true;
            }

            // A value that points to a TableTuple object.
            // return a pointer to its backing storage
            llvm::Value* getTupleStorage(llvm::Value* tuple, const std::string& name) {
                llvm::Function* tupleAddressFn = m_codegenContext->getFunction("tuple_address");
                llvm::Value* storage = builder().CreateCall(tupleAddressFn,
                                                           tuple,
                                                           name);
                return storage;
            }

            void codegenProjectionInline(ProjectionPlanNode* node,
                                         const TupleSchema* inputSchema,
                                         llvm::Value* inputTupleStorage,
                                         const TupleSchema* outputSchema,
                                         llvm::Value* outputTupleStorage) {
                const std::vector<AbstractExpression*>& projectedExprs =
                    node->getOutputColumnExpressions();


                for (int i = 0; i < projectedExprs.size(); ++i) {
                    ExprGenerator generator(m_codegenContext,
                                            getFunction(),
                                            m_builder.get(), inputTupleStorage);
                    llvm::Value* v = generator.generate(inputSchema, projectedExprs[i]);

                    // place the computed expression in the output tuple
                    // Find the offset of the ith column


                }
            }

            void codegenSeqScan(SeqScanPlanNode* node) {
                llvm::LLVMContext &ctx = getLlvmContext();

                if (isTrivialScan(node)) {
                    VOLT_DEBUG("Creating trivial function for scan which does nothing");
                    llvm::Value* retValue = llvm::ConstantInt::get(llvm::Type::getInt8Ty(ctx), 1);
                    builder().CreateRet(retValue);
                    return;
                }

                ProjectionPlanNode* projNode = static_cast<ProjectionPlanNode*>(node->getInlinePlanNode(PLAN_NODE_TYPE_PROJECTION));
                int numInlinedNodes = node->getInlinePlanNodes().size();
                if (numInlinedNodes > 1 || (projNode == NULL && numInlinedNodes > 0)) {
                    throw UnsupportedForCodegenException("limit or agg inlined in scan");
                }

                Table* inputTable = (node->isSubQuery()) ?
                    node->getChildren()[0]->getOutputTable():
                    node->getTargetTable();
                Table* outputTable = node->getOutputTable();

                llvm::BasicBlock *scanLoopEntry = llvm::BasicBlock::Create(getLlvmContext(),
                                                                          "scan_loop_entry",
                                                                          getFunction());
                llvm::BasicBlock *scanLoopBody = llvm::BasicBlock::Create(getLlvmContext(),
                                                                          "scan_loop_body",
                                                                          getFunction());
                llvm::BasicBlock *scanLoopExit = llvm::BasicBlock::Create(getLlvmContext(),
                                                                          "scan_loop_exit",
                                                                          getFunction());

                llvm::Function* tableTempTupleFn = m_codegenContext->getFunction("table_temp_tuple");
                llvm::Value* inputTuple = builder().CreateCall(tableTempTupleFn,
                                                              getInputTable(),
                                                              "input_tuple");
                llvm::Value* outputTuple = inputTuple;
                llvm::Value* outputTupleStorage = NULL;
                if (projNode != NULL) {
                    outputTuple = builder().CreateCall(tableTempTupleFn,
                                                       getOutputTable(),
                                                       "output_tuple");

                    // Get the address of the storage for the output tuple
                    outputTupleStorage = getTupleStorage(outputTuple, "output_tuple_storage");

                }
                llvm::Function* getIterFn = m_codegenContext->getFunction("table_get_iterator");
                llvm::Value* inputIter = builder().CreateCall(getIterFn,
                                                              getInputTable(),
                                                              "input_table_iter");
                builder().CreateBr(scanLoopEntry);

                // The test of the loop condition
                builder().SetInsertPoint(scanLoopEntry);
                llvm::Function* iterGetNextFn = m_codegenContext->getFunction("iterator_next");
                std::vector<llvm::Value*> args;
                args.push_back(inputIter);
                args.push_back(inputTuple);
                llvm::Value* found = builder().CreateCall(iterGetNextFn,
                                                          args);
                llvm::Value *zero = llvm::ConstantInt::get(llvm::Type::getInt8Ty(ctx), 0);
                llvm::Value* cmpResult = builder().CreateICmpNE(found, zero, "tuple_found");
                builder().CreateCondBr(cmpResult, scanLoopBody, scanLoopExit);

                // We have an input row.  Process it.
                builder().SetInsertPoint(scanLoopBody);
                if (projNode != NULL) {
                    llvm::Value* inputTupleStorage = getTupleStorage(inputTuple, "input_tuple_storage");
                    codegenProjectionInline(projNode,
                                            inputTable->schema(),
                                            inputTupleStorage,
                                            outputTable->schema(),
                                            outputTupleStorage);
                }
                llvm::Function* insertTupleFn =
                    m_codegenContext->getFunction("table_insert_tuple_nonvirtual");
                args.clear();
                args.push_back(getOutputTable());
                args.push_back(outputTuple);
                builder().CreateCall(insertTupleFn, args);
                builder().CreateBr(scanLoopEntry);

                // No more rows.
                builder().SetInsertPoint(scanLoopExit);
                llvm::Value* retValue = llvm::ConstantInt::get(llvm::Type::getInt8Ty(ctx), 1);
                builder().CreateRet(retValue);
            }

            llvm::LLVMContext& getLlvmContext() {
                return m_codegenContext->getLlvmContext();
            }

            llvm::IRBuilder<>& builder() {
                return *m_builder;
            }

            CodegenContextImpl* m_codegenContext;
            llvm::Function* m_function;
            boost::scoped_ptr<llvm::IRBuilder<> > m_builder;
        };
    }

    namespace {
        void addPrototypes(llvm::Module* module) {
            llvm::Type* charPtrTy = llvm::Type::getInt8PtrTy(module->getContext());
            llvm::Type* boolTy = llvm::Type::getInt8Ty(module->getContext());
            llvm::Type* voidTy = llvm::Type::getVoidTy(module->getContext());
            module->getOrInsertFunction("table_get_iterator", charPtrTy, charPtrTy, NULL);
            module->getOrInsertFunction("table_temp_tuple", charPtrTy, charPtrTy, NULL);
            module->getOrInsertFunction("table_insert_tuple_nonvirtual", voidTy, charPtrTy, charPtrTy, NULL);

            module->getOrInsertFunction("iterator_next", boolTy, charPtrTy, charPtrTy, NULL);
            module->getOrInsertFunction("tuple_address", charPtrTy, charPtrTy, NULL);
        }
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

        llvm::ExecutionEngine *engine = llvm::EngineBuilder(m_module)
            .setErrorStr(&m_errorString)
            //            .setUseMCJIT(true)
            .create();

        if (! engine) {
            // throwing in a constructor is bad
            // all of this should be in an init method
            // should also release module in this case.
            throw std::exception();
        }

        // m_module now owned by the engine.

        m_executionEngine.reset(engine);

        addPrototypes(m_module);

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

    llvm::Function*
    CodegenContextImpl::getFunction(const std::string& fnName) {
        llvm::Function* fn = m_module->getFunction(fnName);
        assert(fn != NULL);
        return fn;
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
        AbstractPlanNode *node = executor->getPlanNode();
        VOLT_DEBUG("Attempting to compile plan node:\n%s", node->debug().c_str());
        PlanNodeFnCtx planNodeFnCtx(this, executor);
        planNodeFnCtx.init(node);
        boost::timer t;

        try {
            t.restart();
            planNodeFnCtx.codegen(node);
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
