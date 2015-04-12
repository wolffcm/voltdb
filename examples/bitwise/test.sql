
drop procedure insbi if exists;
drop table t if exists;
create table t (bi bigint);

-- This should fail (no digits)
insert into t values (x'');

-- This fails because odd number of digits
insert into t values (x'001');

-- This fails because of too many digits
insert into t values (x'ffffffffffffffffff');


insert into t values (x'ffff');

select bi, hex(bi) from t where bi = x'ffff';
select bi, hex(bi) from t where bi = 65535;

insert into t values (x'ffffffffffffffff');

select bi, hex(bi) from t where bi = -1;
select bi, hex(bi) from t where bi = x'ffffffffffffffff';

insert into t values (x'7fffffffffffffff');
select bi, hex(bi) from t;

delete from t;


insert into t values (x'0001');

select
       bitand(x'ff00', x'00ff'),
       bitor(x'ff00', x'00ff'),
       bitxor(x'f00f', x'00ff')
from t;

select
       hex(bitand(x'ff00', x'00ff')),
       hex(bitor(x'ff00', x'00ff')),
       hex(bitxor(x'f00f', x'00ff'))
from t;

create procedure insbi as
  insert into t values (?);

exec insbi x'0f';
exec insbi x'ffffffffffffffff';

select * from t;
