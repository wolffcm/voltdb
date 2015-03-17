/* This file is part of VoltDB.
 * Copyright (C) 2008-2015 VoltDB Inc.
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

#include <cassert>
#include <boost/algorithm/string.hpp>
#include <boost/geometry.hpp>
#include <boost/geometry/algorithms/append.hpp>
#include <boost/geometry/algorithms/within.hpp>
#include <boost/geometry/geometries/adapted/boost_tuple.hpp>
#include <boost/geometry/geometries/point_xy.hpp>
#include <boost/geometry/geometries/polygon.hpp>
#include <vector>

#include "common/NValue.hpp"
#include "common/PlannerDomValue.h"
#include "expressions/geofunctions.h"
#include "expressions/jsonfunctions.h"

// Treat boost::tuples as cartesian coordinates
BOOST_GEOMETRY_REGISTER_BOOST_TUPLE_CS(boost::geometry::cs::cartesian)


namespace voltdb {

    typedef boost::geometry::model::d2::point_xy<double> Point;
    typedef boost::geometry::model::polygon<boost::geometry::model::d2::point_xy<double> > Polygon;

static void throwGeoJsonFormattingError(const std::string& geoJson) {
    char msg[1024];
    snprintf(msg, sizeof(msg), "Invalid GeoJSON: %s", geoJson.c_str());
    throw SQLException(SQLException::data_exception_invalid_parameter, msg);
}

    static std::string docGet(JsonDocument& doc, const std::string& path) {
        std::string result;
        assert (doc.get(path.c_str(), path.length(), result));

        // JsonDocument will append a trailing newline... why?
        boost::trim(result);
        return result;
    }

static Point geoJsonToPoint(const char* geoJsonStr, int32_t len) {

    // Should I use PlannerDomRoot or JsonDocument here?

    JsonDocument doc(geoJsonStr, len);
    std::string geometryType = docGet(doc, "type");

    if (! boost::iequals("Point", geometryType)) {
        throwGeoJsonFormattingError(geoJsonStr);
    }

    double xCoord = boost::lexical_cast<double>(docGet(doc, "coordinates[0]"));
    double yCoord = boost::lexical_cast<double>(docGet(doc, "coordinates[1]"));

    return Point(xCoord, yCoord);
}

static Polygon geoJsonToPolygon(const char* geoJsonStr, int32_t len) {

    std::cout << "Creating poly from:\n" << geoJsonStr << std::endl;

    PlannerDomRoot domRoot(geoJsonStr);
    PlannerDomValue root = domRoot.rootObject();

    std::string geometryType = root.valueForKey("type").asStr();

    std::cout << "Geometry type is " << geometryType << std::endl;

    if (! boost::iequals("Polygon", geometryType)) {
        throwGeoJsonFormattingError(geoJsonStr);
    }

    // A GeoJSON polygon is an array of rings, which is an array of
    // points, which is a 2-element array of coordinates.
    //
    // The first ring is the outer ring (area inside the ring is part
    // of the polygon).  Subsequent rings enclose negative space that
    // isn't part of the polygon.  E.g., a 2-d donut shape would have
    // both an inner and outer ring.
    //
    // A simple rectangle (one ring):
    // {
    //   "type": "Polygon",
    //   "coordinates": [
    //     [[0.0, 0.0], [0.0, 1.0], [1.0, 1.0], [1.0, 0.0], [0.0, 0.0]]
    //   ]
    // }

    PlannerDomValue outerRing = root.valueForKey("coordinates").valueAtIndex(0);


    // Json::Value ringRoot;
    // Json::Reader reader;
    // assert(reader.parse(outerRing, ringRoot));

    // int32_t numPoints = ringRoot.size();
    // assert(numPoints > 0);

    // std::cout << "Polygon has " << numPoints << " points." << std::endl;

    // JsonDocument ringDoc(outerRing.c_str(), outerRing.length());

int numPoints = outerRing.arrayLen();
    Polygon poly;
    for (int i = 0; i < numPoints; ++i) {
        double x = outerRing.valueAtIndex(i).valueAtIndex(0).asDouble();
        double y = outerRing.valueAtIndex(i).valueAtIndex(0).asDouble();

        // std::ostringstream path;
        // path << "coordinates[0][" << i << "][0]";
        // double x = boost::lexical_cast<double>(docGet(doc, path.str()));

        // path.str("");
        // path << "coordinates[0][" << i << "][1]";
        // double y = boost::lexical_cast<double>(docGet(doc, path.str()));

        boost::geometry::append(poly, Point(x, y));
    }

    //std::cout << "Created polygon " << poly << std::endl;

    return poly;
}

template<> NValue NValue::call<FUNC_VOLT_GEO_WITHIN>(const std::vector<NValue>& arguments) {

    assert(arguments.size() == 2);

    const NValue& nvalPoint = arguments[0];
    const NValue& nvalPoly = arguments[1];

    if (nvalPoint.getValueType() != VALUE_TYPE_VARCHAR) {
        throwCastSQLException(nvalPoint.getValueType(), VALUE_TYPE_VARCHAR);
    }

    if (nvalPoly.getValueType() != VALUE_TYPE_VARCHAR) {
        throwCastSQLException(nvalPoly.getValueType(), VALUE_TYPE_VARCHAR);
    }

    if (nvalPoint.isNull() || nvalPoly.isNull())
        return NValue::getNullValue(VALUE_TYPE_INTEGER);

    const char* jsonStrPoint = reinterpret_cast<char*>(nvalPoint.getObjectValue_withoutNull());
    int32_t len = nvalPoint.getObjectLength_withoutNull();
    Point pt = geoJsonToPoint(jsonStrPoint, len);

    const char* jsonStrPoly = reinterpret_cast<char*>(nvalPoly.getObjectValue_withoutNull());
    len = nvalPoint.getObjectLength_withoutNull();
    Polygon poly = geoJsonToPolygon(jsonStrPoly, len);

    NValue result(VALUE_TYPE_INTEGER);
    boost::tuple<double, double> p = boost::make_tuple(pt.x(), pt.y());
    bool b = boost::geometry::within(p, poly);
    if (b) {
        result.getInteger() = 1;
    }
    else {
        result.getInteger() = 0;
    }

    return result;
}

} // end namespace voltdb
