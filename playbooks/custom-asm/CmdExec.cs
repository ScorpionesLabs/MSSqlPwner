using System;
using Microsoft.SqlServer.Server;
using System.Data.SqlTypes;
using System.Diagnostics;
using System.Data.SqlClient;
using System.Collections.Generic;
using System.Data;

public static class SqlHelper
{
    private static Dictionary<Type, SqlDbType> typeMap;

    // Create and populate the dictionary in the static constructor in mappings may be wrong
    static SqlHelper()
    {
        typeMap = new Dictionary<Type, SqlDbType>();

        typeMap[typeof(string)] = SqlDbType.NVarChar;
        typeMap[typeof(char[])] = SqlDbType.NVarChar;
        typeMap[typeof(byte)] = SqlDbType.TinyInt;
        typeMap[typeof(byte[])] = SqlDbType.Image;
        //typeMap[typeof(sbyte)]        = SqlDbType.TinyInt; - not sure of sqldbtype
        //typeMap[typeof(ushort)]       = SqlDbType.TinyInt; - not sure of sqldbtype
        //typeMap[typeof(uint)]         = SqlDbType.TinyInt; - not sure of sqldbtype
        //typeMap[typeof(ulong)]        = SqlDbType.TinyInt; - not sure of sqldbtype   
        //typeMap[typeof(DateSpan)]     = SqlDbType.TinyInt; - not sure of sqldbtype              
        typeMap[typeof(short)] = SqlDbType.SmallInt;
        typeMap[typeof(int)] = SqlDbType.Int;
        typeMap[typeof(long)] = SqlDbType.BigInt;
        typeMap[typeof(bool)] = SqlDbType.Bit;
        typeMap[typeof(DateTime)] = SqlDbType.DateTime2;
        typeMap[typeof(DateTimeOffset)] = SqlDbType.DateTimeOffset;
        typeMap[typeof(decimal)] = SqlDbType.Money;
        typeMap[typeof(float)] = SqlDbType.Real;
        typeMap[typeof(double)] = SqlDbType.Float;
        typeMap[typeof(TimeSpan)] = SqlDbType.Time;
    }

    // Non-generic argument-based method
    public static SqlDbType GetDbType(Type giveType)
    {
        // Allow nullable types to be handled
        giveType = Nullable.GetUnderlyingType(giveType) ?? giveType;

        if (typeMap.ContainsKey(giveType))
        {
            return typeMap[giveType];
        }

        throw new ArgumentException("is not a supported .NET class");
    }

    // Generic version
    public static SqlDbType GetDbType<T>()
    {
        return GetDbType(typeof(T));
    }
}

public class StoredProcedures
{
    // create method marked as StoredProcedure to start cmd.exe
    // execute the command given inside execCommand then return result
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void execute_command(SqlString execCommand)
    {
        // start cmd.exe process providing arguments not printed to STDOUT
        Process proc = new Process();
        proc.StartInfo.FileName = Environment.GetEnvironmentVariable("ComSpec"); ;
        proc.StartInfo.Arguments = string.Format(@" /C {0}", execCommand);
        proc.StartInfo.UseShellExecute = false;
        proc.StartInfo.RedirectStandardOutput = true;
        proc.Start();

        // retrieve STDOUT using SqlContext.Pipe embedded object
        // start recording, record data, & stop recording into SqlDataRecord object
        SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", System.Data.SqlDbType.NVarChar, 4000));
        SqlContext.Pipe.SendResultsStart(record);
        record.SetString(0, proc.StandardOutput.ReadToEnd().ToString());
        SqlContext.Pipe.SendResultsRow(record);
        SqlContext.Pipe.SendResultsEnd();

        // force cmd.exe to wait until all actions done then close
        proc.WaitForExit();
        proc.Close();
    }

    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void run_query(SqlString execTsql)
    {
        // Run as calling SQL/Windows login    
        using (SqlConnection connection = new SqlConnection("context connection=true"))
        {
            connection.Open();
            SqlCommand command = new SqlCommand(execTsql.ToString(), connection);
            SqlContext.Pipe.ExecuteAndSend(command);
            connection.Close();
        }
    }

    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void run_query_system_service(SqlString execTsql)
    {

        // user connection string builder here, accept query, server, current, user, password - execute as system by default, accept windows creds, sql creds

        // Connection string
        using (SqlConnection connection = new SqlConnection(@"Data Source=127.0.0.1;Initial Catalog=master;Integrated Security=True"))
        {
            connection.Open();
            SqlCommand command = new SqlCommand(execTsql.ToString(), connection);
            command.CommandTimeout = 240;
            SqlDataReader reader = command.ExecuteReader();

            // Create List for Columns
            List<SqlMetaData> OutputColumns = new List<SqlMetaData>(reader.FieldCount);

            // Get schema
            DataTable schemaTable = reader.GetSchemaTable();

            // Get column names, types, and sizes from reader
            for (int i = 0; i < reader.FieldCount; i++)
            {
                // Check if char and string types
                if (typeof(char).Equals(reader.GetFieldType(i)) || typeof(string).Equals(reader.GetFieldType(i)))
                {
                    SqlMetaData OutputColumn = new SqlMetaData(reader.GetName(i), SqlHelper.GetDbType(reader.GetFieldType(i)), 4000);
                    OutputColumns.Add(OutputColumn);
                }
                else
                {

                    // Anything other type
                    SqlMetaData OutputColumn = new SqlMetaData(reader.GetName(i), SqlHelper.GetDbType(reader.GetFieldType(i)));
                    OutputColumns.Add(OutputColumn);
                }
            }

            // Create the record and specify the metadata for the columns.
            SqlDataRecord record = new SqlDataRecord(OutputColumns.ToArray());

            // Mark the begining of the result-set.
            SqlContext.Pipe.SendResultsStart(record);

            // Check for rows
            if (reader.HasRows)
            {
                while (reader.Read())
                {
                    // Iterate through column count, set value for each column in row
                    for (int i = 0; i < reader.FieldCount; i++)
                    {
                        // Add value to the current row/column
                        record.SetValue(i, reader[i]);
                    }

                    // Send the row back to the client.
                    SqlContext.Pipe.SendResultsRow(record);
                }

            }
            else
            {

                // Set values for each column in the row
                record.SetString(0, "No rows found.");

                // Send the row back to the client.
                SqlContext.Pipe.SendResultsRow(record);
            }

            // Mark the end of the result-set.
            SqlContext.Pipe.SendResultsEnd();

            connection.Close();
        }
    }



};