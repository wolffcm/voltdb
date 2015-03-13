/* This file is part of VoltDB.
 * Copyright (C) 2008-2014 VoltDB Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */


//
// Accepts a vote, enforcing business logic: make sure the vote is for a valid
// contestant and that the voter (phone number of the caller) is not above the
// number of allowed votes.
//

package jittester.procedures;

import org.voltdb.ProcInfo;
import org.voltdb.SQLStmt;
import org.voltdb.VoltProcedure;
import org.voltdb.VoltTable;

public class Select extends VoltProcedure {

    // Checks if the vote is for a valid contestant
    public final SQLStmt selectStmt = new SQLStmt(
            "SELECT i, j FROM my_table WHERE i = ?;");

    public long run(int value) throws Exception {

        // Queue up validation statements
        try {
            voltQueueSQL(selectStmt, value);
            VoltTable vt = voltExecuteSQL()[0];
            assert(vt.advanceRow());
            boolean hasRow = vt.advanceRow();
            if (! hasRow)
                throw new Exception("0 rows?!");
            long i = vt.getLong(0);
            long j = vt.getLong(1);
            if (i != value)
                throw new Exception("i was " + i + "!");
            if (j != value)
                throw new Exception("j was " + j + "!");

            hasRow = vt.advanceRow();
            if (hasRow)
                throw new Exception("Too many rows?!");

        } catch(Exception ex) {
            System.out.println("Error: " + ex.getMessage());
            throw ex;
        }

        return 1;
    }
}
