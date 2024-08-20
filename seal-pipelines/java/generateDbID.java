// Generates database ID for AR licensing
// example POSTGRESQL|POSTGRES|ARSYSTEM
//  dbType.toUpperCase() "|" + dbHostName.toUpperCase() + "|" + dbName.toUpperCase()
// POSTGRESQL | SQL -- SQL SERVER | SQL -- ORACLE

import java.util.Base64;
import java.util.Base64.Encoder;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

class generateDbID {

  static void usage() {
    String usageMessage = "Usage: java generateDbID \"DB_TYPE\" \"DB_HOSTNAME\" \"DB_NAME\"\n"
                        + "Where:\n"
                        + "  DB_TYPE is one of postgres|mssql|oracle\n"
                        + "  DB_HOSTNAME is the server where the database is running or the JDBC connect string if used.\n"
                        + "  DB_NAME is the name of the database.\n"
                        + "Quote values if they contain spaces.";
      System.out.println(usageMessage);
      System.exit(1);
  }

  public static void main(String[] args) {

      // Check for correct usage
      if (args.length != 3) {
        usage();
      }

    String dbID;
    String sourceForDbID;
    String dbType = "";
    String dbHostName = args[1];
    String dbName = args[2];

    switch (args[0].toUpperCase()) {
      case "MSSQL":
        dbType = "SQL -- SQL SERVER";
        break;
      case "ORACLE":
        dbType = "SQL -- ORACLE";
        break;
      case "POSTGRES":
        dbType = "POSTGRESQL";
        break;
      default:
        System.out.println("Error - Invalid DB_TYPE");
        usage();
    }

    sourceForDbID =  dbType.toUpperCase() + "|" + dbHostName.toUpperCase() + "|" + dbName.toUpperCase();

    try {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(sourceForDbID.getBytes(StandardCharsets.UTF_8));
        byte[] hashedBytes = md.digest();
        Encoder encoder = Base64.getEncoder().withoutPadding();
        dbID = encoder.encodeToString(hashedBytes);
        System.out.println(dbID);
      } catch (Exception e) {}
   }
}
