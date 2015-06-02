#!/bin/bash

rm *.jar
rm procedures/approxcountdistinct/*.class
rm client/approxcountdistinct/*.class

javac procedures/approxcountdistinct/*.java
ls procedures/approxcountdistinct/*.class
jar cf procs.jar -C procedures/ approxcountdistinct

javac client/approxcountdistinct/*.java
ls client/approxcountdistinct/*.class
jar cf client.jar -C client/ approxcountdistinct

ls -l *.jar

voltdb create &
sleep 5

sqlcmd < ddl.sql

export CLASSPATH=${CLASSPATH}:/home/cwolff/alt_workspace/voltdb/tests/test_apps/approx-count-distinct/client.jar

java -Dlog4j.configuration=file://${LOG4J} approxcountdistinct.Benchmark
