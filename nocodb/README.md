# SQL Injection in nocodb when used with Oracle database
## Summary

Nocodb versions up to 0.204.0 are prone to SQL injection vulnerability that could allows an attacker with the right access to query the Oracle database. 

## Details

The `hasTable` function within the [OracleClient.ts](https://github.com/nocodb/nocodb/blob/0.204.0/packages/nocodb/src/db/sql-client/lib/oracle/OracleClient.ts) file can be abused by attackers to inject arbitrary Oracle SQL queries, potentially leading to unauthorized access or manipulation of the underlying Oracle database. The vulnerable code is located in the `hasTable` function, where user-supplied input (`args.tn`) is directly interpolated into the SQL query without proper sanitization.

```
async hasTable(args: any = {}) {
  const _func = this.hasTable.name;
  const result = new Result();
  log.api(`${_func}:args:`, args);

  try {
    const rows = await this.raw(
      `select TABLE_NAME as tn FROM all_tables WHERE OWNER = '${this.connectionConfig.connection.user}' AND tn = '${args.tn}'`,
    );
   // ..snip..
}

// ..snip..

async createTableIfNotExists(args) {
    const _func = this.createTableIfNotExists.name;
    const result = new Result();
    log.api(`${_func}:args:`, args);

    try {
      /** ************** START : create _evolution table if not exists *************** */
      const exists = await this.hasTable({ tn: args.tn });

      // ..snip..
}
```

## Impact

This vulnerability may lead to unauthorized access, data manipulation, or potential exposure of sensitive information in the Oracle database.

## Remediation

To address the SQL injection vulnerability in the hasTable function within the OracleClient.ts file, it is strongly recommended to use parameterized queries or prepared statements to separate user input from the SQL query. This helps prevent SQL injection attacks by treating user input as data rather than executable code.

## Credit

Discovered by @v0lck3r (Oussama RAHALI), Feb 2024.

