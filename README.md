# JWT Sept Login Server Setup
This guide shows how to get an sept login server up and running, using a postgres database container as example.

## Generate Keypair for signing and verifying JWT Keys

```bash
openssl ecparam -genkey -name prime256v1 -noout -out private_key.pem
openssl ec -in private_key.pem -pubout -out public_key.pem
```

## Set Up Postgres with Docker

```bash
docker run --name sept-login -p 5432:5432 -e POSTGRES_PASSWORD=password -d postgres
```

## Configure Database Connection

Set the following environment variable:

```bash
export DATABASE_SECRET="host=localhost user=postgres password=password dbname=postgres port=5432 sslmode=disable TimeZone=Europe/Oslo"
```

## Run the Application

```bash
go run main.go
```

Note: Ensure you have Docker and Go installed on your system before running these commands.