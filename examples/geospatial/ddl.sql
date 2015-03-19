file -inlinebatch EOF
-- With population of at least 100,000
create table us_cities (
       id integer not null primary key,
       name varchar(128) not null,
       state varchar(128) not null,
       population bigint not null,
       geo_json varchar(128) not null
);
partition table us_cities on column id;

create table us_states (
       id integer not null primary key,
       postalcode varchar(2) not null,
       name varchar(128) not null,
       geo_json varchar(500000 bytes) not null
);


-- radius of earth is 3959 miles;
create procedure areaOfState as
       select name, geo_area(geo_json) * 3959*3959 as area_in_miles
       from us_states
       where name = ?;

create procedure citiesInState as
       select us_cities.name, us_cities.population
       from us_states
         inner join us_cities
         on geo_within(us_cities.geo_json, us_states.geo_json) = 1
       where us_states.name = ?
       order by us_cities.population desc;

create procedure numCitiesPerState as
       select us_states.name, count(*)
       from us_states
         inner join us_cities
         on geo_within(us_cities.geo_json, us_states.geo_json) = 1
       group by us_states.name
       order by count(*) desc;

create procedure populationPerState as
       select us_states.name as state,
              sum(us_cities.population) as population
       from us_states
         inner join us_cities
         on geo_within(us_cities.geo_json, us_states.geo_json) = 1
       group by us_states.name
       order by population desc;
EOF
