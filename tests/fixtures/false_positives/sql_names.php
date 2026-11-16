<?php
// Backtick-quoted column followed by a comma is not the end of the SQL string.
$sql = "SELECT COUNT(*) as `count`, status FROM `$table` GROUP BY status";
// Fragments and class-internal names, not request values.
$sql = "SELECT idinvalidation FROM `$table` WHERE idsite = ? AND $reportClause LIMIT 1";
$sql = "SELECT * FROM " . $this->tokenTable . " WHERE `login` = ? AND " . $expired['sql'];
$row = Db::fetchOne("SELECT MAX($idCol) FROM " . Common::prefixTable($table));
