#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE USER aip WITH PASSWORD 'aip';
    CREATE DATABASE aip OWNER aip;
    CREATE USER tap WITH PASSWORD 'tap';
    CREATE DATABASE tap OWNER tap;
EOSQL
