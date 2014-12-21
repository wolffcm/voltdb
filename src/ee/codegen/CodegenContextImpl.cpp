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
// #ifdef VOLT_LOG_LEVEL
// #undef VOLT_LOG_LEVEL
// #endif

// #define VOLT_LOG_LEVEL VOLT_LEVEL_DEBUG

#include "codegen/CodegenContextImpl.hpp"
#include "codegen/ExprGenerator.hpp"
#include "codegen/PlanNodeFnGenerator.hpp"
#include "codegen/PredFnGenerator.hpp"
#include "common/SQLException.h"
#include "common/TupleSchema.h"
#include "common/debuglog.h"
#include "common/types.h"
#include "common/value_defs.h"
#include "common/ValuePeeker.hpp"
#include "common/StringRef.h"
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
#include "llvm/IR/GlobalValue.h"
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
    bool success = llvm::llvm_start_multithreaded();
    (void)success;
    assert(success);
    llvm::InitializeNativeTarget();
}

namespace voltdb {

    llvm::StructType* getTableTupleType(llvm::LLVMContext &ctx) {
        llvm::Type* ptrToCharTy = llvm::Type::getInt8PtrTy(ctx);
        return llvm::StructType::get(ptrToCharTy, ptrToCharTy, NULL);
    }

    llvm::IntegerType* getNativeSizeType(llvm::LLVMContext& ctx) {
        static const unsigned sizeSizeInBits = static_cast<unsigned>(sizeof(size_t) * 8);
        llvm::IntegerType* nativeSizeTy = llvm::Type::getIntNTy(ctx, sizeSizeInBits);
        return nativeSizeTy;
    }

    llvm::StructType* getStringRefType(llvm::LLVMContext &ctx) {
        llvm::Type* ptrToCharTy = llvm::Type::getInt8PtrTy(ctx);
        return llvm::StructType::get(ptrToCharTy,
                                     getNativeSizeType(ctx),
                                     llvm::Type::getInt8Ty(ctx),
                                     NULL);
    }

    llvm::PointerType* getPtrToStringRefType(llvm::LLVMContext &ctx) {
        return llvm::PointerType::getUnqual(getStringRefType(ctx));
    }

    llvm::PointerType* getPtrToPtrToStringRefType(llvm::LLVMContext &ctx) {
        return llvm::PointerType::getUnqual(getPtrToStringRefType(ctx));
    }


    ValueType getExprType(const AbstractExpression* expr) {
            switch (expr->getExpressionType()) {
            case EXPRESSION_TYPE_COMPARE_EQUAL:
            case EXPRESSION_TYPE_COMPARE_NOTEQUAL:
            case EXPRESSION_TYPE_COMPARE_LESSTHAN:
            case EXPRESSION_TYPE_COMPARE_GREATERTHAN:
            case EXPRESSION_TYPE_COMPARE_LESSTHANOREQUALTO:
            case EXPRESSION_TYPE_COMPARE_GREATERTHANOREQUALTO:
            case EXPRESSION_TYPE_COMPARE_LIKE:
            case EXPRESSION_TYPE_COMPARE_IN:
            case EXPRESSION_TYPE_CONJUNCTION_AND:
            case EXPRESSION_TYPE_CONJUNCTION_OR:
                return VALUE_TYPE_BOOLEAN;
            default:
                return expr->getValueType();
            }
        }
} // end namespace voltdb

extern "C" {

    // These are C wrappers for functions called from
    // generated code

    void codegen_debug_ptr(size_t i64Num, void* ptr) {
        VOLT_TRACE("---");
        VOLT_TRACE("  Here's a number: %ld", i64Num);
        VOLT_TRACE("  Here's a pointer: %p", ptr);
    }

    void codegen_debug_size(size_t i64Num, size_t data) {
        VOLT_TRACE("---");
        VOLT_TRACE("  Here's a number: %ld", i64Num);
        VOLT_TRACE("  Here's a size_t as a signed number: %ld", data);
    }
} // end extern "C" definitions

namespace voltdb { namespace {

        // Add the extern "C" functions above to the module
        void addPrototypes(llvm::Module* module) {

            PlanNodeFnGenerator::addExternalPrototypes(module);
            ExprGenerator::addExternalPrototypes(module);

            llvm::LLVMContext& ctx = module->getContext();
            llvm::Type* charPtrTy = llvm::Type::getInt8PtrTy(ctx);
            llvm::Type* voidTy = llvm::Type::getVoidTy(ctx);

            module->getOrInsertFunction("codegen_debug_ptr",
                                        voidTy,
                                        getNativeSizeType(ctx),
                                        charPtrTy,
                                        NULL);

            module->getOrInsertFunction("codegen_debug_size",
                                        voidTy,
                                        getNativeSizeType(ctx),
                                        getNativeSizeType(ctx),
                                        NULL);
        }

    } // end anonymous namespace

    CodegenContextImpl::CodegenContextImpl()
        : m_llvmContext()
        , m_module(NULL)
        , m_executionEngine()
        , m_passManager()
        , m_errorString()
        , m_externalTypesMap()
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

    void CodegenContextImpl::registerExternalTy(const std::string& typeName) {
        llvm::StructType *ty = llvm::StructType::create(getLlvmContext(),
                                                        typeName);
        m_externalTypesMap[typeName] = ty;
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

    llvm::IntegerType* CodegenContextImpl::getIntPtrType() {
        return m_executionEngine->getDataLayout()->getIntPtrType(*m_llvmContext);
    }

    template<typename T>
    static void dumpObj(T* obj, const std::string& desc, int forLogLevel) {
        if (VOLT_LOG_LEVEL <= forLogLevel) {
            std::string irDump;
            llvm::raw_string_ostream rso(irDump);
            obj->print(rso, NULL);
            VOLT_DEBUG("%s LLVM IR: \n%s", desc.c_str(), irDump.c_str());
        }
    }

    llvm::Value* CodegenContextImpl::getColumnOffset(const TupleSchema* schema, int columnId) {
        const TupleSchema::ColumnInfo *columnInfo = schema->getColumnInfo(columnId);
        uint32_t intOffset = TUPLE_HEADER_SIZE + columnInfo->offset;
        llvm::Type* indexType = ExprGenerator::getLlvmType(*m_llvmContext, VALUE_TYPE_INTEGER);

        llvm::Value* offset = llvm::ConstantInt::get(indexType, intOffset);
        return offset;
    }

    void*
    CodegenContextImpl::generateCode(llvm::Function* fn) {
        void* nativeFunction = NULL;
        boost::timer t;

        // Dump the unoptimized fn
        dumpObj(fn, "Unoptimized", VOLT_LEVEL_DEBUG);

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
        dumpObj(fn, "Optimized", VOLT_LEVEL_TRACE);

        return nativeFunction;
    }

    PredFunction
    CodegenContextImpl::compilePredicate(const std::string& fnName,
                                     const TupleSchema* tupleSchema,
                                     const AbstractExpression* expr) {
        VOLT_TRACE("Attempting to compile predicate:\n%s", expr->debug(true).c_str());
        PredFnGenerator predFnGenerator(this, fnName);
        boost::timer t;

        try {
            t.restart();
            predFnGenerator.codegen(tupleSchema, expr);
            VOLT_DEBUG("Predicate IR construction took %f seconds", t.elapsed());
        }
        catch (UnsupportedForCodegenException& ex) {
            predFnGenerator.getFunction()->eraseFromParent();
            VOLT_DEBUG("Aborted compilation: %s", ex.getMessage().c_str());

            // EE will fall back to interpreting function
            return NULL;
        }

        return (PredFunction)generateCode(predFnGenerator.getFunction());
    }

    PlanNodeFunction
    CodegenContextImpl::compilePlanNode(AbstractExecutor *executor) {
        AbstractPlanNode *node = executor->getPlanNode();
        VOLT_DEBUG("Attempting to compile plan node: %s", node->debug().c_str());
        PlanNodeFnGenerator planNodeFnGenerator(this, executor);
        planNodeFnGenerator.init(node);
        boost::timer t;

        try {
            t.restart();
            planNodeFnGenerator.codegen(node);
            VOLT_DEBUG("Plan node IR construction took %f seconds", t.elapsed());
        }
        catch (UnsupportedForCodegenException& ex) {
            planNodeFnGenerator.getFunction()->eraseFromParent();
            VOLT_DEBUG("Aborted compilation: %s", ex.getMessage().c_str());

            // EE will fall back to interpreting function
            return NULL;
        }

        return (PlanNodeFunction)generateCode(planNodeFnGenerator.getFunction());
    }

    void CodegenContextImpl::shutdownLlvm() {
        llvm::llvm_shutdown();
    }
}
