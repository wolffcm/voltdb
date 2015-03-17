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

import org.voltdb.BackendTarget;
import org.voltdb.VoltTable;
import org.voltdb.client.Client;
import org.voltdb.client.ClientResponse;
import org.voltdb.client.NoConnectionsException;
import org.voltdb.client.ProcCallException;
import org.voltdb.compiler.VoltProjectBuilder;
import org.voltdb_testprocs.regressionsuites.fixedsql.Insert;

/**
 * Tests for SQL functions in the geo-spatial domain.
 */

public class TestGeoFunctions extends RegressionSuite {

    public void testGeoWithin() throws Exception {
        Client client = getClient();

        // Wyoming: a nice big state with easily modeled borders
        client.callProcedure("regions.Insert", 0, "Wyoming",
                "{\n"
                + "\"type\": \"Polygon\",\n"
                + "\"coordinates\": [\n"
                + "  ["
                + "    [-111.03955, 41.005431], "
                + "    [-111.037011, 45.020203], "
                + "    [-104.034125, 45.005161], "
                + "    [-104.063028, 41.001106], "
                + "    [-111.03955, 41.005431] "
                + "  ]\n"
                + "]\n"
                + "}\n");

        client.callProcedure("regions.Insert", 1, "Colorado",
                "{\n"
                + "\"type\": \"Polygon\",\n"
                + "\"coordinates\": [\n"
                + "  ["
                + "    [-109.032233, 40.983839], "
                + "    [-102.020617, 40.986844], "
                + "    [-102.023014, 37.000261], "
                + "    [-109.031208, 36.999322], "
                + "    [-109.032233, 40.983839] "
                + "  ]\n"
                + "]\n"
                + "}\n");

        // Casper: a random city that is clearly within the
        // borders of Wyoming
        client.callProcedure("points.Insert", 0, "Casper",
                "{"
                + "\"type\": \"Point\","
                + "\"coordinates\": [-106.325, 42.834722]"
                + "}");

        // Denver: a random city that is clearly within the
        // borders of Colorado
        client.callProcedure("points.Insert", 1, "Denver",
                "{"
                + "\"type\": \"Point\","
                + "\"coordinates\": [-104.881111, 39.761944]"
                + "}");


        VoltTable vt = client.callProcedure("@AdHoc",
                "select pts.name || ' is within ' || regs.name "
                + "from points as pts "
                + "inner join regions as regs "
                + "on geo_within(pts.geom, regs.geom) = 1"
                + "order by pts.id")
                .getResults()[0];
        assertEquals(2, vt.getRowCount());
        vt.advanceRow();
        assertEquals("Casper is within Wyoming", vt.getString(0));
        vt.advanceRow();
        assertEquals("Denver is within Colorado", vt.getString(0));
    }

    //
    // JUnit / RegressionSuite boilerplate
    //
    public TestGeoFunctions(String name) {
        super(name);
    }

    static public junit.framework.Test suite() {

        VoltServerConfig config = null;
        MultiConfigSuiteBuilder builder =
            new MultiConfigSuiteBuilder(TestGeoFunctions.class);
        boolean success;

        VoltProjectBuilder project = new VoltProjectBuilder();
        final String literalSchema =
                "create table regions (\n" +
                "  id integer primary key,\n" +
                "  name varchar(64) not null,\n" +
                "  geom varchar(512)\n" +
                ");\n" +
                "\n" +
                "create table points (\n" +
                "  id integer primary key,\n" +
                "  name varchar(64) not null,\n" +
                "  geom varchar(512)\n" +
                ");\n";
        try {
            project.addLiteralSchema(literalSchema);
        } catch (IOException e) {
            assertFalse(true);
        }

        // CONFIG #1: Local Site/Partition running on JNI backend
        config = new LocalCluster("fixedsql-onesite.jar", 1, 1, 0, BackendTarget.NATIVE_EE_JNI);
        success = config.compile(project);
        assertTrue(success);
        builder.addServerConfig(config);

        return builder;
    }
}
