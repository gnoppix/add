/**
 *-------------------------------------------------------------------------------
 * Name: Gnoppix Linux - Services
 * Architecture: all
 * Date: 2002-2026 by Gnoppix Linux
 * Author: Andreas Mueller
 * Website: https://www.gnoppix.com
 * Licence: Business Source License (BSL / BUSL)
 * You can use the code for free if your company or organisation doesn't have more than 2 people.
 *-------------------------------------------------------------------------------
 */

import { execFile } from 'child_process'
import { promisify } from 'util'

const execFileAsync = promisify(execFile)

// Path to the Add CLI binary
const ADD_CLI = process.env.ADD_CLI_PATH || 'add'

export interface NullId {
  id: string
  fingerprint: string
}

export interface Contact {
  nullId: string
  fingerprint: string
}

export class AddCLI {
  private cliPath: string

  constructor(cliPath?: string) {
    this.cliPath = cliPath || ADD_CLI
  }

  async runCommand(args: string[]): Promise<string> {
    try {
      // Pass args as a real array so values with spaces (aliases, messages)
      // are not mangled. `add-contact` and `alias` take positional args, NOT flags.
      const { stdout } = await execFileAsync(this.cliPath, args)
      return stdout.trim()
    } catch (error) {
      throw new Error(`CLI error: ${error}`)
    }
  }

  async init(): Promise<NullId> {
    const output = await this.runCommand(['init'])
    const idMatch = output.match(/Null ID:\s*(NN-[A-Z0-9-]+)/)
    const fpMatch = output.match(/Fingerprint:\s*([A-Z0-9]+)/)
    return { id: idMatch?.[1] || '', fingerprint: fpMatch?.[1] || '' }
  }

  async getMyId(): Promise<NullId> {
    const output = await this.runCommand(['id'])
    const idMatch = output.match(/Null ID:\s*(NN-[A-Z0-9-]+)/)
    const fpMatch = output.match(/Fingerprint:\s*([A-Z0-9]+)/)
    return { id: idMatch?.[1] || '', fingerprint: fpMatch?.[1] || '' }
  }

  async register(): Promise<void> {
    await this.runCommand(['register'])
  }

  async addContact(nullId: string, fingerprint: string): Promise<void> {
    // CLI: `add-contact <NULL_ID> <FINGERPRINT>` (positional, no --fingerprint flag)
    await this.runCommand(['add-contact', nullId, fingerprint])
  }

  async contacts(): Promise<Contact[]> {
    const output = await this.runCommand(['contacts'])
    const contacts: Contact[] = []
    const lines = output.split('\n')
    for (const line of lines) {
      // CLI format: "  NN-xxxx-xxxx -> FINGERPRINT"
      const match = line.match(/(NN-[A-Z0-9-]+)\s*->\s*([A-Z0-9]+)/)
      if (match) contacts.push({ nullId: match[1], fingerprint: match[2] })
    }
    return contacts
  }

  async alias(name: string, nullId: string): Promise<void> {
    await this.runCommand(['alias', name, nullId])
  }

  async send(nullId: string, message: string, ttl?: string): Promise<void> {
    const args = ['send', nullId, message]
    if (ttl) args.push('--ttl', ttl)
    await this.runCommand(args)
  }

  async read(): Promise<Array<{id: string; content: string; timestamp: string}>> {
    // TODO: Parse CLI output format
    await this.runCommand(['read'])
    return []
  }
}

// Export singleton for main process use
export const cli = new AddCLI()
export default AddCLI
