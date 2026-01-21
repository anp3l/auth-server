import fs from 'fs';
import path from 'path';

export interface TemplateVariables {
  [key: string]: string | number;
}

/**
 * Simple template engine to replace {{name}} variables with values
 */
export class TemplateEngine {
  private templatesPath: string;
  private templateCache: Map<string, string>;

  constructor() {
    this.templatesPath = path.join(__dirname, 'templates');
    this.templateCache = new Map();
  }

  /**
   * Reads a template from the filesystem (with caching)
   */
  private readTemplate(templateName: string): string {
    // Check cache
    if (this.templateCache.has(templateName)) {
      return this.templateCache.get(templateName)!;
    }

    const templatePath = path.join(this.templatesPath, `${templateName}.html`);
    
    if (!fs.existsSync(templatePath)) {
      throw new Error(`Template not found: ${templateName}`);
    }

    const template = fs.readFileSync(templatePath, 'utf-8');
    
    // Cache in development is disabled, in production it is enabled
    if (process.env.NODE_ENV === 'production') {
      this.templateCache.set(templateName, template);
    }

    return template;
  }

  /**
   * Compile a template by replacing the {{name}} variables with values
   */
  compile(templateName: string, variables: TemplateVariables): string {
    let html = this.readTemplate(templateName);

    Object.entries(variables).forEach(([key, value]) => {
      const regex = new RegExp(`{{${key}}}`, 'g');
      html = html.replace(regex, String(value));
    });

    const unresolvedVars = html.match(/{{[\w]+}}/g);
    if (unresolvedVars && process.env.NODE_ENV === 'development') {
      console.warn(`⚠️  Unresolved template variables in ${templateName}:`, unresolvedVars);
    }

    return html;
  }

  clearCache(): void {
    this.templateCache.clear();
  }
}

// Singleton instance
let templateEngineInstance: TemplateEngine | null = null;

export function getTemplateEngine(): TemplateEngine {
  if (!templateEngineInstance) {
    templateEngineInstance = new TemplateEngine();
  }
  return templateEngineInstance;
}
