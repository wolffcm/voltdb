
create table data (
       pk bigint not null primary key,
       attr bigint not null,
);

partition table data on column pk;

load classes procs.jar;
create procedure from class approxcountdistinct.DoCount;
