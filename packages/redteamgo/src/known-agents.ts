/**
 * Curated registry of declared bots and AI agents — the guest list's
 * "who's who." Matching is by distinctive User-Agent token, not full UA
 * string (operators append version/contact info that changes).
 *
 * This is deliberately small and factual. RedTeamGo does not compete on
 * detection breadth — unknown automation falls to the heuristics in
 * classify.ts, and operators can extend via `knownAgents`. `verification`
 * records how an operator lets you confirm the claim (published IP ranges /
 * reverse DNS / Web Bot Auth); the check itself is the injected ipVerifier.
 */

export type AgentCategory =
  | "search_crawler"
  | "ai_training"
  | "ai_assistant"
  | "ai_search"
  | "social_preview"
  | "other";

export interface KnownAgent {
  /** stable kebab-case id — used as the receipt actor id and allow-list key */
  id: string;
  operator: string;
  /** case-insensitive UA substrings that identify this agent */
  ua_tokens: string[];
  category: AgentCategory;
  /** how the operator says you can verify the claim, if at all */
  verification?: "ip_ranges" | "reverse_dns" | "web_bot_auth";
}

export const KNOWN_AGENTS: KnownAgent[] = [
  // Search crawlers
  { id: "googlebot", operator: "Google", ua_tokens: ["Googlebot"], category: "search_crawler", verification: "ip_ranges" },
  { id: "bingbot", operator: "Microsoft", ua_tokens: ["bingbot"], category: "search_crawler", verification: "ip_ranges" },
  { id: "applebot", operator: "Apple", ua_tokens: ["Applebot"], category: "search_crawler", verification: "ip_ranges" },
  { id: "duckduckbot", operator: "DuckDuckGo", ua_tokens: ["DuckDuckBot"], category: "search_crawler", verification: "ip_ranges" },
  { id: "yandexbot", operator: "Yandex", ua_tokens: ["YandexBot"], category: "search_crawler", verification: "reverse_dns" },
  { id: "baiduspider", operator: "Baidu", ua_tokens: ["Baiduspider"], category: "search_crawler", verification: "reverse_dns" },
  { id: "amazonbot", operator: "Amazon", ua_tokens: ["Amazonbot"], category: "search_crawler", verification: "ip_ranges" },

  // AI — training/index crawlers
  { id: "gptbot", operator: "OpenAI", ua_tokens: ["GPTBot"], category: "ai_training", verification: "ip_ranges" },
  { id: "claudebot", operator: "Anthropic", ua_tokens: ["ClaudeBot"], category: "ai_training", verification: "ip_ranges" },
  { id: "google-extended", operator: "Google", ua_tokens: ["Google-Extended"], category: "ai_training" },
  { id: "applebot-extended", operator: "Apple", ua_tokens: ["Applebot-Extended"], category: "ai_training" },
  { id: "meta-externalagent", operator: "Meta", ua_tokens: ["meta-externalagent"], category: "ai_training" },
  { id: "bytespider", operator: "ByteDance", ua_tokens: ["Bytespider"], category: "ai_training" },
  { id: "ccbot", operator: "Common Crawl", ua_tokens: ["CCBot"], category: "ai_training" },
  { id: "cohere-ai", operator: "Cohere", ua_tokens: ["cohere-ai"], category: "ai_training" },

  // AI — search/answer crawlers
  { id: "oai-searchbot", operator: "OpenAI", ua_tokens: ["OAI-SearchBot"], category: "ai_search", verification: "ip_ranges" },
  { id: "claude-searchbot", operator: "Anthropic", ua_tokens: ["Claude-SearchBot"], category: "ai_search", verification: "ip_ranges" },
  { id: "perplexitybot", operator: "Perplexity", ua_tokens: ["PerplexityBot"], category: "ai_search", verification: "ip_ranges" },

  // AI — on-demand user-triggered fetchers (a human asked an assistant)
  { id: "chatgpt-user", operator: "OpenAI", ua_tokens: ["ChatGPT-User"], category: "ai_assistant", verification: "ip_ranges" },
  { id: "claude-user", operator: "Anthropic", ua_tokens: ["Claude-User"], category: "ai_assistant", verification: "ip_ranges" },
  { id: "perplexity-user", operator: "Perplexity", ua_tokens: ["Perplexity-User"], category: "ai_assistant", verification: "ip_ranges" },

  // Social link preview fetchers
  { id: "facebook-preview", operator: "Meta", ua_tokens: ["facebookexternalhit", "FacebookBot"], category: "social_preview" },
  { id: "twitterbot", operator: "X", ua_tokens: ["Twitterbot"], category: "social_preview" },
  { id: "linkedinbot", operator: "LinkedIn", ua_tokens: ["LinkedInBot"], category: "social_preview" },
  { id: "slackbot", operator: "Slack", ua_tokens: ["Slackbot"], category: "social_preview" },
  { id: "discordbot", operator: "Discord", ua_tokens: ["Discordbot"], category: "social_preview" },
  { id: "whatsapp", operator: "Meta", ua_tokens: ["WhatsApp"], category: "social_preview" },
  { id: "telegrambot", operator: "Telegram", ua_tokens: ["TelegramBot"], category: "social_preview" },
];
