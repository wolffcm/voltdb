/* This file is part of VoltDB.
 * Copyright (C) 2008-2017 VoltDB Inc.
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

#ifndef _VOLTDB_LARGETABLEITERATOR_H
#define _VOLTDB_LARGETABLEITERATOR_H

#include <vector>

#include "common/executorcontext.hpp"
#include "common/tabletuple.h"
#include "common/LargeTempTableBlockCache.h"

#include "storage/table.h"
#include "storage/LargeTempTable.h"

namespace voltdb {

class LargeTableIterator {

    friend class LargeTempTable;

public:

    LargeTableIterator(const LargeTableIterator& that)
        : m_tupleLength(that.m_tupleLength)
        , m_activeTuples(that.m_activeTuples)
        , m_foundTuples(that.m_foundTuples)
        , m_blockIdIterator(that.m_blockIdIterator)
        , m_currBlock(that.m_currBlock)
        , m_currBlockId(that.m_currBlockId)
        , m_dataPtr(that.m_dataPtr)
        , m_blockOffset(that.m_blockOffset)
    {
    }

    inline bool next(TableTuple& out);
    bool hasNext() const;

    inline virtual ~LargeTableIterator();

protected:
 LargeTableIterator(Table* table, std::vector<int64_t>::iterator start)
     : m_tupleLength(table->m_tupleLength)
        , m_activeTuples(table->m_tupleCount)
        , m_foundTuples(0)
        , m_blockIdIterator(start)
        , m_currBlock(nullptr)
        , m_currBlockId(-1)
        , m_dataPtr(NULL)
        , m_blockOffset(0)
    {
    }

private:
    const uint32_t m_tupleLength;
    const uint32_t m_activeTuples;

    uint32_t m_foundTuples;

    std::vector<int64_t>::iterator m_blockIdIterator;
    LargeTempTableBlock* m_currBlock;
    int64_t m_currBlockId;
    char * m_dataPtr;
    uint32_t m_blockOffset;
};


bool LargeTableIterator::next(TableTuple& out) {
    if (m_foundTuples < m_activeTuples) {
        if (m_currBlock == NULL ||
            m_blockOffset >= m_currBlock->unusedTupleBoundary()) {
            LargeTempTableBlockCache* lttCache = ExecutorContext::getExecutorContext()->lttBlockCache();

            if (m_currBlock != NULL) {
                lttCache->unpinBlock(m_currBlockId);
            }

            // delete as you go logic should be here

            m_currBlockId = *m_blockIdIterator;
            m_currBlock = lttCache->fetchBlock(m_currBlockId);

            m_dataPtr = m_currBlock->address();

            ++m_blockIdIterator;

            m_blockOffset = 0;
        } // end if we need to transition to the next block
        else {
            m_dataPtr += m_tupleLength;
        }

        out.move(m_dataPtr);

        ++m_foundTuples;
        ++m_blockOffset;

        return true;
    } // end if there are still more tuples

    return false;
}

LargeTableIterator::~LargeTableIterator() {
    if (m_currBlock != NULL) {
        LargeTempTableBlockCache* lttCache = ExecutorContext::getExecutorContext()->lttBlockCache();
        lttCache->unpinBlock(m_currBlockId);
    }
 }

} // namespace voltdb

#endif // _VOLTDB_LARGETABLEITERATOR_H
