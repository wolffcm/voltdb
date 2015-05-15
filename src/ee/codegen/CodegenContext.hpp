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

#ifndef _CODEGENCONTEXT_HPP_
#define _CODEGENCONTEXT_HPP_

#include <string>
#include "boost/scoped_ptr.hpp"

#include "common/types.h"

namespace voltdb {

    class AbstractExecutor;
    class AbstractExpression;
    class TupleSchema;
    class CodegenContextImpl;

    class CodegenContext {
    public:
        CodegenContext();

        PredFunction compilePredicate(const std::string& fnName,
                                      const TupleSchema* tupleSchema,
                                      const AbstractExpression* expr);

        ~CodegenContext();

        static void shutdownLlvm();

    private:

        boost::scoped_ptr<CodegenContextImpl> m_impl;

   };

}

#endif
