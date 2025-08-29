"""
Migration script to fix key_ column format in keys table.
Some keys may be stored as 'kid:key' format when they should only contain the 'key' part.
"""

import logging

from sqlalchemy import text

from getwvkeys.models.Key import Key as KeyModel

logger = logging.getLogger("getwvkeys")


def run_migration(db):
    """
    Fix keys that are stored in 'kid:key' format to only store the 'key' part.
    """
    logger.info("Starting key format migration...")

    # Find keys that contain ':' which indicates they might be in 'kid:key' format
    keys_with_colon = KeyModel.query.filter(KeyModel.key_.contains(":")).all()

    if not keys_with_colon:
        logger.info("No keys found with ':' character. Migration not needed.")
        return

    logger.info(f"Found {len(keys_with_colon)} keys that may need fixing...")

    fixed_count = 0
    skipped_count = 0
    error_count = 0

    BATCH_SIZE = 100  # Number of fixes before committing
    batch_counter = 0

    for key_obj in keys_with_colon:
        try:
            # Check if this key is in 'kid:key' format
            if ":" in key_obj.key_:
                parts = key_obj.key_.split(":")

                # Validate that we have exactly 2 parts and the first part matches the kid
                if len(parts) == 2:
                    potential_kid, potential_key = parts

                    # Check if the first part matches the kid (with or without dashes)
                    kid_no_dash = key_obj.kid.replace("-", "")
                    potential_kid_no_dash = potential_kid.replace("-", "")

                    if kid_no_dash.lower() == potential_kid_no_dash.lower():
                        # This is definitely in 'kid:key' format, fix it
                        old_key = key_obj.key_
                        key_obj.key_ = potential_key

                        logger.debug(
                            f"Fixed key {key_obj.kid}: '{old_key}' -> '{potential_key}'"
                        )
                        fixed_count += 1
                        batch_counter += 1
                    else:
                        # The part before ':' doesn't match the kid, so this might be a legitimate key with ':'
                        logger.debug(
                            f"Skipping key {key_obj.kid}: colon found but doesn't match kid pattern"
                        )
                        skipped_count += 1
                else:
                    # Multiple colons or other format, skip
                    logger.debug(
                        f"Skipping key {key_obj.kid}: unexpected format with {len(parts)} parts"
                    )
                    skipped_count += 1
        except Exception as e:
            logger.error(f"Error processing key {key_obj.kid}: {e}")
            error_count += 1

        # Commit every BATCH_SIZE fixes
        if batch_counter >= BATCH_SIZE:
            try:
                db.session.commit()
                logger.info(f"Committed batch of {batch_counter} fixes.")
            except Exception as e:
                db.session.rollback()
                logger.error(f"Failed to commit batch: {e}")
                raise
            batch_counter = 0

    # Commit any remaining changes
    if fixed_count > 0 and batch_counter > 0:
        try:
            db.session.commit()
            logger.info(f"Committed final batch of {batch_counter} fixes.")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to commit final batch: {e}")
            raise

    if fixed_count > 0:
        logger.info(f"Migration completed successfully!")
        logger.info(f"Fixed: {fixed_count} keys")
        logger.info(f"Skipped: {skipped_count} keys")
        if error_count > 0:
            logger.warning(f"Errors: {error_count} keys")
    else:
        logger.info("No keys needed fixing.")


def validate_migration(db):
    """
    Validate that the migration was successful by checking for any remaining 'kid:key' patterns.
    """
    logger.info("Validating migration...")

    # Check for any remaining keys that might still be in wrong format
    suspicious_keys = db.session.execute(
        text(
            """
            SELECT kid, key_ FROM keys 
            WHERE key_ LIKE CONCAT(REPLACE(kid, '-', ''), ':%')
            OR key_ LIKE CONCAT(kid, ':%')
            LIMIT 10
        """
        )
    ).fetchall()

    if suspicious_keys:
        logger.warning(
            f"Found {len(suspicious_keys)} potentially problematic keys after migration:"
        )
        for kid, key in suspicious_keys:
            logger.warning(f"  {kid}: {key}")
        return False
    else:
        logger.info("Migration validation passed - no problematic keys found.")
        return True


if __name__ == "__main__":
    from getwvkeys.main import app, db

    with app.app_context():
        run_migration(db)
        validate_migration(db)
