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

#include "codegen/CodegenContext.hpp"
#include "codegen/CodegenContextImpl.hpp"

namespace voltdb {

    CodegenContext::CodegenContext()
        : m_impl(new CodegenContextImpl())
    {
    }

    CodegenContext::~CodegenContext() {
    }

    PredFunction
    CodegenContext::compilePredicate(const std::string& fnName,
                                     const TupleSchema* tupleSchema,
                                     const AbstractExpression* expr) {
        return m_impl->compilePredicate(fnName, tupleSchema, expr);
    }

    void CodegenContext::shutdownLlvm() {
        CodegenContextImpl::shutdownLlvm();
    }

    void CodegenContext::startLlvm() {
        CodegenContextImpl::startLlvm();
    }
}
