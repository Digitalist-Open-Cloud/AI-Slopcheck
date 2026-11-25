<?php
class Drop
{
    protected function getTable()
    {
        return Common::prefixTable(self::$rawPrefix);
    }

    public function execute()
    {
        // Checked where it is assigned, and a table name the class builds itself.
        $db_name = DatabaseSsl::assertValidDatabaseName($this->config['db_name']);
        $args = ["--execute=SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = '$db_name'"];
        $sql = "SELECT idsegment FROM " . $this->getTable() . " ORDER BY `ts_created`";
    }
}
