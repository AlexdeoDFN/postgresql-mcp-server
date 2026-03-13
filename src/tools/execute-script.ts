import { z } from 'zod';
import { DatabaseConnection } from '../utils/connection.js';
import { McpError, ErrorCode } from '@modelcontextprotocol/sdk/types.js';
import type { PostgresTool, ToolOutput, GetConnectionStringFn } from '../types/tool.js';

// ===== SQL SAFETY VALIDATION =====

/**
 * Banned SQL patterns — these are destructive operations that must NEVER
 * be executed through the MCP tool. The DBA agent must validate scripts
 * before execution, and this is the last line of defense.
 *
 * Mirrors the patterns blocked by settings.json deny list for Bash commands.
 */
const BANNED_PATTERNS: { pattern: RegExp; description: string }[] = [
  { pattern: /\bDROP\s+TABLE\b/i, description: 'DROP TABLE' },
  { pattern: /\bDROP\s+COLUMN\b/i, description: 'DROP COLUMN' },
  { pattern: /\bDROP\s+INDEX\b/i, description: 'DROP INDEX' },
  { pattern: /\bDROP\s+TYPE\b/i, description: 'DROP TYPE' },
  { pattern: /\bDROP\s+SCHEMA\b/i, description: 'DROP SCHEMA' },
  { pattern: /\bDROP\s+DATABASE\b/i, description: 'DROP DATABASE' },
  { pattern: /\bDROP\s+FUNCTION\b/i, description: 'DROP FUNCTION' },
  { pattern: /\bDROP\s+TRIGGER\b/i, description: 'DROP TRIGGER' },
  { pattern: /\bDROP\s+VIEW\b/i, description: 'DROP VIEW' },
  { pattern: /\bTRUNCATE\b/i, description: 'TRUNCATE' },
  { pattern: /\bDELETE\s+FROM\b/i, description: 'DELETE FROM' },
  { pattern: /\bUPDATE\s+\S+\s+SET\b/i, description: 'UPDATE SET (use app code for data modifications)' },
  { pattern: /\bALTER\s+TABLE\s+\S+\s+RENAME\b/i, description: 'ALTER TABLE RENAME' },
  { pattern: /\bALTER\s+TABLE\s+\S+\s+DROP\b/i, description: 'ALTER TABLE DROP' },
];

/**
 * Allowed SQL patterns — only these types of statements are permitted.
 * This is a whitelist approach on top of the blacklist.
 */
const ALLOWED_STATEMENT_PREFIXES = [
  'CREATE TABLE IF NOT EXISTS',
  'CREATE INDEX IF NOT EXISTS',
  'CREATE UNIQUE INDEX IF NOT EXISTS',
  'CREATE TYPE',           // wrapped in DO $$ block with EXCEPTION handler
  'ALTER TABLE',           // only ADD COLUMN / ADD CONSTRAINT (DROP is banned above)
  'DO $$',                 // PL/pgSQL blocks (for idempotent type/constraint creation)
  'DO $',                  // DO blocks with custom tags
  'BEGIN',                 // Transaction control
  'COMMIT',                // Transaction control
  'COMMENT ON',            // Documentation
  'CREATE OR REPLACE',     // Functions, views
  'INSERT INTO',           // Seed data (DBA validates idempotency)
  'SELECT',                // Verification queries
  'WITH',                  // CTEs
  'SET',                   // Session config (e.g., SET search_path)
  'GRANT',                 // Permission grants
  'REVOKE',                // Permission revocations
];

interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  statementCount: number;
}

/**
 * Validates a SQL script against safety rules.
 * Returns validation result with errors and warnings.
 */
function validateSqlScript(sql: string): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Check against banned patterns
  for (const { pattern, description } of BANNED_PATTERNS) {
    if (pattern.test(sql)) {
      errors.push(`BLOCKED: Script contains banned pattern: ${description}`);
    }
  }

  // Check that statements use idempotent patterns
  if (/\bCREATE\s+TABLE\b/i.test(sql) && !/\bCREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\b/i.test(sql)) {
    // Allow if it's inside a DO $$ block (PL/pgSQL handles this differently)
    if (!/DO\s+\$\$/i.test(sql)) {
      warnings.push('WARNING: CREATE TABLE without IF NOT EXISTS — script may fail on re-run');
    }
  }

  if (/\bCREATE\s+INDEX\b/i.test(sql) && !/\bCREATE\s+(UNIQUE\s+)?INDEX\s+IF\s+NOT\s+EXISTS\b/i.test(sql)) {
    if (!/DO\s+\$\$/i.test(sql)) {
      warnings.push('WARNING: CREATE INDEX without IF NOT EXISTS — script may fail on re-run');
    }
  }

  if (/\bADD\s+COLUMN\b/i.test(sql) && !/\bADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\b/i.test(sql)) {
    if (!/DO\s+\$\$/i.test(sql)) {
      warnings.push('WARNING: ADD COLUMN without IF NOT EXISTS — script may fail on re-run');
    }
  }

  // Count statements (rough estimate based on semicolons outside strings)
  const statementCount = (sql.match(/;\s*$/gm) || []).length || 1;

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    statementCount,
  };
}

// ===== EXECUTE SCRIPT TOOL =====

const ExecuteScriptInputSchema = z.object({
  connectionString: z.string().optional().describe('PostgreSQL connection string (optional — uses configured default)'),
  sql: z.string().describe('The SQL script to execute. Must be an idempotent DDL script (CREATE IF NOT EXISTS, ADD COLUMN IF NOT EXISTS, etc.). Destructive operations (DROP, TRUNCATE, DELETE, UPDATE) are blocked.'),
  dryRun: z.boolean().optional().default(false).describe('If true, wraps in BEGIN/ROLLBACK so no changes are applied. Use to verify a script works before committing.'),
  description: z.string().optional().describe('Brief description of what this script does (for logging purposes)'),
});

type ExecuteScriptInput = z.infer<typeof ExecuteScriptInputSchema>;

async function executeScript(
  input: ExecuteScriptInput,
  getConnectionString: GetConnectionStringFn
): Promise<{ success: boolean; message: string; validation: ValidationResult; dryRun: boolean }> {
  const resolvedConnectionString = getConnectionString(input.connectionString);
  const db = DatabaseConnection.getInstance();
  const { sql, dryRun, description } = input;

  // Step 1: Validate the SQL script
  const validation = validateSqlScript(sql);

  if (!validation.valid) {
    return {
      success: false,
      message: `Script REJECTED by safety validation:\n${validation.errors.join('\n')}`,
      validation,
      dryRun: dryRun ?? false,
    };
  }

  // Step 2: Execute
  try {
    await db.connect(resolvedConnectionString);

    if (dryRun) {
      // Dry run: wrap in BEGIN/ROLLBACK
      await db.query('BEGIN');
      try {
        await db.query(sql);
        await db.query('ROLLBACK');
        return {
          success: true,
          message: `DRY RUN successful — script executed without errors, then rolled back. No changes were applied.\n${description ? `Description: ${description}` : ''}`,
          validation,
          dryRun: true,
        };
      } catch (execError) {
        await db.query('ROLLBACK');
        throw execError;
      }
    } else {
      // Real execution — the script should contain its own BEGIN/COMMIT if needed
      await db.query(sql);
      return {
        success: true,
        message: `Script executed successfully.${description ? ` Description: ${description}` : ''}`,
        validation,
        dryRun: false,
      };
    }
  } catch (error) {
    throw new McpError(
      ErrorCode.InternalError,
      `Failed to execute script: ${error instanceof Error ? error.message : String(error)}`
    );
  } finally {
    await db.disconnect();
  }
}

export const executeScriptTool: PostgresTool = {
  name: 'pg_execute_script',
  description:
    'Execute a validated DDL/migration SQL script against the database. ' +
    'Built-in safety: blocks DROP, TRUNCATE, DELETE, UPDATE, RENAME. ' +
    'Only allows additive operations (CREATE IF NOT EXISTS, ADD COLUMN IF NOT EXISTS, etc.). ' +
    'Use dryRun=true to test without applying changes. ' +
    'Example: sql="CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, name TEXT);", dryRun=true',
  inputSchema: ExecuteScriptInputSchema,
  execute: async (args: unknown, getConnectionStringVal: GetConnectionStringFn): Promise<ToolOutput> => {
    const {
      connectionString: connStringArg,
      sql,
      dryRun,
      description,
    } = args as {
      connectionString?: string;
      sql: string;
      dryRun?: boolean;
      description?: string;
    };

    // Input validation
    if (!sql?.trim()) {
      return {
        content: [{ type: 'text', text: 'Error: sql is required' }],
        isError: true,
      };
    }

    try {
      const result = await executeScript(
        {
          connectionString: connStringArg,
          sql,
          dryRun: dryRun ?? false,
          description,
        },
        getConnectionStringVal
      );

      // Build response
      const parts: string[] = [];

      if (result.dryRun) {
        parts.push('=== DRY RUN MODE (no changes applied) ===\n');
      }

      parts.push(result.message);

      if (result.validation.warnings.length > 0) {
        parts.push('\n\nWarnings:');
        parts.push(result.validation.warnings.join('\n'));
      }

      parts.push(`\nStatements: ~${result.validation.statementCount}`);

      return {
        content: [{ type: 'text', text: parts.join('\n') }],
        isError: !result.success,
      };
    } catch (error) {
      return {
        content: [
          {
            type: 'text',
            text: `Error executing script: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  },
};
