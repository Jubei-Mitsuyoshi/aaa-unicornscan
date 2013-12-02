
drop table "os_fingerprint";
drop table "banner";
drop table "scan_bucket";
drop table "scan";
drop table "scan_queue";

create table "scan_queue"
(
	"scan_queue_id"	unsigned bigint not null auto_increment = 0,
	"target"	varchar(200) not null,
	"portstr"	varchar(200) default null,
	"scanmode"	varchar(10) default null,
	"pps"		bigint default null,
	"srcaddr"	varchar(200) default null,
	"srcport"	int default null,
	"fantaip"	smallint default null,		-- 1: use fantaip, 0: don't use fantaip
	"fingerprint"	smallint default null,
	"brokencrc"	varchar(3) default null,
	"ipttl"		smallint default null,
	"iptos"		smallint default null,
	"repeats"	bigint default null,
	"outputmods"	varchar(200) default null,	-- database,p0f
	"extraargs"	varchar(200) default null,	-- S:no-shuffle, D:no-defpayload
	"pcapfilter"	varchar(200) default null,
	primary key("scan_queue_id")
);

create sequence scan_id_seq;
create table "scan"
(
	"scan_id"	unsigned bigint not null auto_increment = 0,
	"s_time"	bigint not null,
	"e_time"	bigint not null,
	"addrmax"	bigint not null,
	"addrmin"	bigint not null,
	"portstr"	varchar(200) not null,
	"scanmode"	smallint not null,
	"pps"		bigint not null,
	"srcaddr"	bigint not null,
	"srcport"	int not null,
	"fingerprint"	int not null,
	"tcpflags"	int not null,
	"active_plgroups"smallint not null,
	"dronestr"	varchar(200) not null,
	"ipttl"		smallint not null,
	"iptos"		smallint not null,
	"ipoffset"	int not null,
	"repeats"	bigint default null,
	"pcapfilter"	varchar(200) not null,
	primary key("scan_id")
);

create table "scan_bucket"
(
	"scan_bucket_id"unsigned bigint not null auto_increment = 0,
        "scan_id"	bigint not null,
	"protocol"	smallint not null,
        "host_addr"	bigint not null, 		-- ipv4 only obviously
        "trace_addr"    bigint not null,
        "dport"         int not null,
        "sport"         int not null,
        "type"		int not null,
        "subtype"       int not null,
        "ttl"           smallint not null,
        "u_tstamp"	bigint not null,
        "u_utstamp"	bigint not null,
	primary key ("scan_bucket_id")
);

create table "os_fingerprint"
(
	"scan_bucket_id"bigint not null,
	"os"	varchar(200) not null
);

create table "banner"
(
	"scan_bucket_id"bigint not null,
	"banner"	varchar(200) not null
);
