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

package org.voltdb.regressionsuites;

import java.io.IOException;
import java.util.Random;

import org.voltdb.BackendTarget;
import org.voltdb.VoltTable;
import org.voltdb.client.Client;
import org.voltdb.client.NoConnectionsException;
import org.voltdb.client.ProcCallException;
import org.voltdb.compiler.VoltProjectBuilder;

public class TestApproxCountDistinctSuite extends RegressionSuite {

    private static void fillTable(Client client, String tbl) throws NoConnectionsException, IOException, ProcCallException {
        Random r = new Random(777);
        for (int i = 0; i < 1000; ++i) {

            double d;
            do {
                d = r.nextGaussian() * 1000;
            } while (d > Long.MAX_VALUE || d <= Long.MIN_VALUE);

            long val = (long) d;
            client.callProcedure(tbl + ".Insert", i, val);
        }
    }

    public void testSimple() throws Exception
    {
        Client client = getClient();

        VoltTable vt = client.callProcedure("@AdHoc", "select approx_count_distinct(bi) from r;")
                .getResults()[0];
        assertTrue(vt.advanceRow());
        assertEquals(0.0, vt.getDouble(0));
        assertFalse(vt.advanceRow());

        fillTable(client, "r");

        System.out.println("Finished filling table!");

        vt = client.callProcedure("@AdHoc",
                "select approx_count_distinct(bi), count(distinct bi)  from r;")
                .getResults()[0];
        System.out.println(vt);
    }

    public void testDistributed() throws Exception {
        Client client = getClient();

        // This still sends all the rows over the network.
        // Need to rework the planner to do this right.
        VoltTable vt = client.callProcedure("@Explain", "select approx_count_distinct(bi) from p;")
                .getResults()[0];
        System.out.println(vt);

        vt = client.callProcedure("@AdHoc", "select approx_count_distinct(bi) from p;")
                .getResults()[0];
        assertTrue(vt.advanceRow());
        assertEquals(0.0, vt.getDouble(0));
        assertFalse(vt.advanceRow());

        fillTable(client, "p");

        System.out.println("Finished filling table!");

        vt = client.callProcedure("@AdHoc",
                "select approx_count_distinct(bi) from p;")
                .getResults()[0];
        System.out.println(vt);
    }

    public TestApproxCountDistinctSuite(String name) {
        super(name);
    }

    static public junit.framework.Test suite() {

        VoltServerConfig config = null;
        MultiConfigSuiteBuilder builder = new MultiConfigSuiteBuilder(TestApproxCountDistinctSuite.class);
        VoltProjectBuilder project = new VoltProjectBuilder();
        final String literalSchema =
                "CREATE TABLE r ( " +
                        "pk integer primary key not null, " +
                        "bi bigint " +
                        ");" +
                        "CREATE TABLE p ( " +
                        "pk integer primary key not null, " +
                        "bi bigint " +
                        ");" +
                        "partition table p on column pk;" +
                        "";
        try {
            project.addLiteralSchema(literalSchema);
        } catch (IOException e) {
            assertFalse(true);
        }
        boolean success;

        config = new LocalCluster("testApproxCountDistinctSuite-onesite.jar", 2, 1, 0, BackendTarget.NATIVE_EE_JNI);
        success = config.compile(project);
        assert(success);
        builder.addServerConfig(config);

        config = new LocalCluster("testApproxCountDistinctSuite-onesite.jar", 1, 1, 0, BackendTarget.NATIVE_EE_JNI);
        success = config.compile(project);
        assert(success);
        builder.addServerConfig(config);

        return builder;
    }
}
