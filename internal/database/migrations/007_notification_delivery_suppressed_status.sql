ALTER TABLE notification_deliveries
  MODIFY COLUMN status ENUM('success','failure','suppressed') NOT NULL;
