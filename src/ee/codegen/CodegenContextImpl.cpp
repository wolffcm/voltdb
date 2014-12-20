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

    voltdb::TableIterator* table_get_iterator(voltdb::Table* table) {
        return &(table->iteratorDeletingAsWeGo());
    }

    voltdb::TableTuple* table_temp_tuple(voltdb::Table* table) {
        return &(table->tempTuple());
    }

    void table_insert_tuple_nonvirtual(voltdb::TempTable* table, voltdb::TableTuple* tuple) {
        table->insertTupleNonVirtual(*tuple);
    }

    const voltdb::TupleSchema* table_schema(voltdb::Table* table) {
        return table->schema();
    }

    bool iterator_next(voltdb::TableIterator* iterator, voltdb::TableTuple* tuple) {
        return iterator->next(*tuple);
    }

    char* stringref_get(voltdb::StringRef* sr) {
        return sr->get();
    }

    void stringref_debug(voltdb::StringRef* sr) {
#if VOLT_LOG_LEVEL<=VOLT_LEVEL_TRACE
        if (sr != NULL) {
            VOLT_TRACE("StringRef addr %p", sr);
            VOLT_TRACE("StringRef get() %p", sr->get());

            const char mask = ~static_cast<char>(OBJECT_NULL_BIT | OBJECT_CONTINUATION_BIT);

            char *data = sr->get();
            char contBit = data[0] & OBJECT_CONTINUATION_BIT;
            VOLT_TRACE("  data[0] & OBJECT_CONTINUATION_BIT: %d", contBit);
            char nullBit = data[0] & OBJECT_NULL_BIT;
            VOLT_TRACE("  data[0] & OBJECT_NULL_BIT: %d", nullBit);
            char shortDataSize = data[0] & mask;
            VOLT_TRACE("  shortDataSize: %d", shortDataSize);
        }
        else {
            VOLT_TRACE("StringRef is NULL");
        }
#endif
    }

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
            llvm::LLVMContext& ctx = module->getContext();
            llvm::Type* charPtrTy = llvm::Type::getInt8PtrTy(ctx);
            llvm::Type* boolTy = llvm::Type::getInt8Ty(ctx);
            llvm::Type* voidTy = llvm::Type::getVoidTy(ctx);
            llvm::Type* ptrToTupleTy = llvm::PointerType::getUnqual(getTableTupleType(ctx));

            module->getOrInsertFunction("table_get_iterator", charPtrTy, charPtrTy, NULL);
            module->getOrInsertFunction("table_temp_tuple", ptrToTupleTy, charPtrTy, NULL);
            module->getOrInsertFunction("table_insert_tuple_nonvirtual", voidTy, charPtrTy, ptrToTupleTy, NULL);
            module->getOrInsertFunction("table_schema", charPtrTy, charPtrTy, NULL);

            module->getOrInsertFunction("iterator_next", boolTy, charPtrTy, ptrToTupleTy, NULL);

            module->getOrInsertFunction("stringref_get", charPtrTy, getPtrToStringRefType(ctx), NULL);

            // Man page defines strncmp like this
            //   int strncmp(const char *s1, const char *s2, size_t n);
            static const unsigned intSizeInBits = static_cast<unsigned>(sizeof(int) * 8);
            llvm::Type* nativeIntTy = llvm::Type::getIntNTy(ctx, intSizeInBits);
            llvm::Type* nativeSizeTy = getNativeSizeType(ctx);
            module->getOrInsertFunction("strncmp", nativeIntTy,
                                        charPtrTy, charPtrTy, nativeSizeTy, NULL);

            // Also need memcpy to insert into varchar fields into tuples
            //   void *memcpy(void *restrict dst, const void *restrict src, size_t n);
            module->getOrInsertFunction("memcpy",  charPtrTy,
                                        charPtrTy, charPtrTy, nativeSizeTy, NULL);

            llvm::Type* ptrToStringRef = llvm::PointerType::getUnqual(getStringRefType(ctx));
            module->getOrInsertFunction("stringref_debug",
                                        voidTy,
                                        ptrToStringRef,
                                        NULL);
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
        llvm::Value* offset = llvm::ConstantInt::get(getLlvmType(VALUE_TYPE_INTEGER), intOffset);
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
