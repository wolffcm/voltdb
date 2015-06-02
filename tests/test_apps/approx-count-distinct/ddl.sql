-- 500,000 drivers
-- Each does 32 trips per day
-- 16M trips per day total
-- About 370 departures and arrivals per second
-- Age out rows older than 1/2 hour
create table trips (
       tripId bigint not null primary key,
       driverId bigint not null,

       startRegionId bigint not null,
       startTs timestamp not null,

       endRegionId bigint,
       endTs timestamp,

       constraint uniq_endts_tripid unique (endTs, tripId),

       constraint row_limit limit partition rows 333300
         execute (
           delete from trips
           where endTs < to_timestamp(second, since_epoch(second, now) - 1800)
           order by endTs, tripId
           limit 100
         )
);

partition table trips on column tripId;

load classes procs.jar;
create procedure from class approxcountdistinct.Initialize;
create procedure DistinctDriversByRegionApprox as
  select
    bitand(startRegionId, X'7C00000000000000') as reg,
    approx_count_distinct(driverId) as cnt
  from trips
  group by reg
  order by cnt desc;

create procedure DistinctDriversByRegionExact as
  select
    bitand(startRegionId, X'7C00000000000000') as reg,
    count(distinct driverId) as cnt
  from trips
  group by reg
  order by cnt desc;
