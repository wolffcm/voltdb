#!/bin/bash

vdb voltdb create &

sleep 5

vdb sqlcmd < test.sql
