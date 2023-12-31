create table if not exists users
(
    id         bigint primary key generated by default as identity,
    email      varchar(255) not null unique,
    first_name varchar(50)  not null,
    last_name  varchar(50)  not null,
    password   varchar(255) not null,
    role varchar(20) not null ,
    status varchar(20)
);