/* This file is part of VoltDB.
 * Copyright (C) 2008-2015 VoltDB Inc.
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

package approxcountdistinct;

import java.util.Random;

import org.voltdb.SQLStmt;
import org.voltdb.VoltProcedure;
import org.voltdb.types.TimestampType;

public class Initialize extends VoltProcedure
{
    private static final int NUM_ROWS = 333000;
    private static final int BATCH_SIZE = 64;
    private static final int NUM_BATCHES = NUM_ROWS / BATCH_SIZE;

    private static final SQLStmt insStmt = new SQLStmt("insert into trips values (?, ?, ?, ?, ?, ?)");

    public long run() {

        System.out.println("Inserting " + NUM_ROWS + " rows into trips table:");
        long tripId = 0;
        Random rand = new Random(777);
        while (tripId < NUM_ROWS) {
            for (int j = 0; j < BATCH_SIZE; ++j) {
                if (tripId >= NUM_ROWS)
                    continue;

                voltQueueSQL(insStmt,
                        tripId++,
                        rand.nextInt(500000),

                        rand.nextLong(),
                        new TimestampType(),

                        rand.nextLong(),
                        new TimestampType()
                        );
            }
            voltExecuteSQL();
            // print status message every 300 batches
            if (tripId % (BATCH_SIZE * 300) == 0) {
                System.out.println("  Inserted " + tripId + " rows.");
            }
        }
        System.out.println("Finished inserting " + tripId + " rows.");

        return 0;
    }
}
