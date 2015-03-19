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
#include <vector>

#include <boost/algorithm/string.hpp>
#include <boost/geometry.hpp>
#include <boost/geometry/algorithms/append.hpp>
#include <boost/geometry/algorithms/area.hpp>
#include <boost/geometry/algorithms/correct.hpp>
#include <boost/geometry/algorithms/within.hpp>
#include <boost/geometry/core/cs.hpp>
#include <boost/geometry/geometries/adapted/boost_tuple.hpp>
#include <boost/geometry/geometries/point_xy.hpp>
#include <boost/geometry/geometries/polygon.hpp>
#include <boost/geometry/multi/algorithms/append.hpp>
#include <boost/geometry/multi/geometries/multi_polygon.hpp>

#include "common/NValue.hpp"
#include "common/PlannerDomValue.h"
#include "common/ValuePeeker.hpp"
#include "expressions/geofunctions.h"

namespace voltdb {

namespace bg = boost::geometry;

typedef bg::cs::spherical_equatorial<bg::degree> CoordSys;

// Points are defined using doubles
//typedef bg::model::point<double, 2, CoordSys> Point;
typedef bg::model::d2::point_xy<double, CoordSys> Point;

typedef bg::model::polygon<Point> Polygon;
typedef bg::model::multi_polygon<Polygon> MultiPolygon;

static void throwGeoJsonFormattingError(const std::string& msg) {
    char exMsg[1024];
    snprintf(exMsg, sizeof(exMsg), "Invalid GeoJSON: %s", msg.c_str());
    throw SQLException(SQLException::data_exception_invalid_parameter, exMsg);
}

static Point geoJsonToPoint(const PlannerDomValue& root) {

    std::string geometryType = root.valueForKey("type").asStr();
    if (! boost::iequals("Point", geometryType)) {
        throwGeoJsonFormattingError("expected value of \"type\" to be \"Point\"");
    }

    PlannerDomValue coords = root.valueForKey("coordinates");
    double xCoord = coords.valueAtIndex(0).asDouble();
    double yCoord = coords.valueAtIndex(1).asDouble();

    return Point(xCoord, yCoord);
}

static Polygon geoJsonToPolygon(const PlannerDomValue& root) {

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
    int numPoints = outerRing.arrayLen();
    Polygon poly;
    for (int i = 0; i < numPoints; ++i) {
        double x = outerRing.valueAtIndex(i).valueAtIndex(0).asDouble();
        double y = outerRing.valueAtIndex(i).valueAtIndex(1).asDouble();
        bg::append(poly, Point(x, y));
    }

    return poly;
}

// static void debugPoly(const Polygon& poly) {
//     std::cout << "Polygon: [\n";
//     for (auto p : poly.outer()) {
//         std::cout << "  (" << p.x() << ", " << p.y() << ")\n";
//     }
//     std::cout << "]\n";

//     if (! poly.inners().empty()) {
//         std::cout << "Inner rings:\n";
//         for (auto inner : poly.inners()) {
//             std::cout << "[\n";
//             for (auto p : inner) {
//                 std::cout << "  (" << p.x() << ", " << p.y() << ")\n";
//             }
//             std::cout << "[\n";
//         }
//     }
// }

static MultiPolygon geoJsonToMultiPolygon(const PlannerDomValue& root) {
    MultiPolygon multiPoly;

    PlannerDomValue polys = root.valueForKey("coordinates");
    int numPolys = polys.arrayLen();
    for (int i = 0; i < numPolys; ++i) {

        PlannerDomValue rings = polys.valueAtIndex(i);
        int numRings = rings.arrayLen();
        assert(numRings >= 1); // for now only support one ring: the outer one.

        Polygon poly;
        for (int ringIdx = 0; ringIdx < numRings; ++ringIdx) {

            PlannerDomValue ring = rings.valueAtIndex(ringIdx);
            int numPoints = ring.arrayLen();
            for (int j = 0; j < numPoints; ++j) {
                double x = ring.valueAtIndex(j).valueAtIndex(0).asDouble();
                double y = ring.valueAtIndex(j).valueAtIndex(1).asDouble();
                if (ringIdx == 0) {
                    // the outer ring
                    bg::append(poly, Point(x, y));
                }
                else {
                    // an inner ring
                    bg::append(poly, Point(x, y), ringIdx - 1);
                }
            }
        }

        multiPoly.push_back(poly);
    }

    // for (auto poly : multiPoly) {
    //     debugPoly(poly);
    // }

    bg::correct(multiPoly);

    return multiPoly;
}

static std::string geometryType(const PlannerDomValue &domVal) {
    if (! domVal.hasKey("type"))
        throwGeoJsonFormattingError("did not find key \"type\"");
    return domVal.valueForKey("type").asStr();
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
    PlannerDomRoot pdrPoint(jsonStrPoint);
    PlannerDomValue pdvPoint = pdrPoint.rootObject();
    assert (boost::iequals(geometryType(pdvPoint), "Point"));
    Point pt = geoJsonToPoint(pdvPoint);

    const char* jsonStrPoly = reinterpret_cast<char*>(nvalPoly.getObjectValue_withoutNull());
    PlannerDomRoot pdrPoly(jsonStrPoly);
    PlannerDomValue pdvPoly = pdrPoly.rootObject();

    bool b;

    // It could be a polygon or multi-polygon
    if (boost::iequals(geometryType(pdvPoly), "Polygon")) {
        Polygon poly = geoJsonToPolygon(pdvPoly);
        b = bg::within(pt, poly);
    }
    else {
        assert(boost::iequals(geometryType(pdvPoly), "MultiPolygon"));
        MultiPolygon multiPoly = geoJsonToMultiPolygon(pdvPoly);
        b = bg::within(pt, multiPoly);
    }

    NValue result(VALUE_TYPE_INTEGER);
    if (b) {
        result.getInteger() = 1;
    }
    else {
        result.getInteger() = 0;
    }

    return result;
}

    template<> NValue NValue::callUnary<FUNC_VOLT_GEO_AREA>() const {

        if (getValueType() != VALUE_TYPE_VARCHAR) {
            throwCastSQLException(getValueType(), VALUE_TYPE_VARCHAR);
        }

        if (isNull())
            return NValue::getNullValue(VALUE_TYPE_INTEGER);

        const char* jsonStrPoly = reinterpret_cast<char*>(getObjectValue_withoutNull());
        PlannerDomRoot pdrPoly(jsonStrPoly);
        PlannerDomValue pdvPoly = pdrPoly.rootObject();

        double area;

        // It could be a polygon or multi-polygon
        if (boost::iequals(geometryType(pdvPoly), "Polygon")) {
            Polygon poly = geoJsonToPolygon(pdvPoly);
            area = bg::area(poly);
        }
        else {
            assert(boost::iequals(geometryType(pdvPoly), "MultiPolygon"));
            MultiPolygon multiPoly = geoJsonToMultiPolygon(pdvPoly);
            area = bg::area(multiPoly);
        }

        NValue result(VALUE_TYPE_DOUBLE);
        result.getDouble() = area;

        return result;
    }

template<> NValue NValue::call<FUNC_VOLT_GEO_DISTANCE>(const std::vector<NValue>& arguments) {

    assert(arguments.size() == 2);
    Point pts[2];

    for (int i = 0; i < 2; ++i) {
        const NValue& nval = arguments[i];

        if (nval.getValueType() != VALUE_TYPE_VARCHAR) {
            throwCastSQLException(nval.getValueType(), VALUE_TYPE_VARCHAR);
        }

        if (nval.isNull()) {
            return NValue::getNullValue(VALUE_TYPE_DOUBLE);
        }

        const char* json = reinterpret_cast<char*>(nval.getObjectValue_withoutNull());
        PlannerDomRoot pdr(json);
        PlannerDomValue pdv = pdr.rootObject();
        assert (boost::iequals(geometryType(pdv), "Point"));
        pts[i] = geoJsonToPoint(pdv);
    }

    double dist = bg::distance(pts[0], pts[1]);
    NValue result(VALUE_TYPE_DOUBLE);
    result.getDouble() = dist;
    return result;
}

    // Interesting geo functions:
    //   centroid
    //   distance
    //   num_geometries
    //   num_interior_rings
    //   num_points
    //   perimeter
    //   within

} // end namespace voltdb
