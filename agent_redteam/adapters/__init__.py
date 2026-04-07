from agent_redteam.adapters.callable import CallableAdapter

__all__ = ["CallableAdapter", "LLMAdapter", "LangChainAdapter", "OpenAIAgentsAdapter", "McpProxyAdapter"]


def __getattr__(name: str):
    if name == "LLMAdapter":
        from agent_redteam.adapters.llm import LLMAdapter

        return LLMAdapter
    if name == "LangChainAdapter":
        from agent_redteam.adapters.langchain import LangChainAdapter

        return LangChainAdapter
    if name == "OpenAIAgentsAdapter":
        from agent_redteam.adapters.openai_agents import OpenAIAgentsAdapter

        return OpenAIAgentsAdapter
    if name == "McpProxyAdapter":
        from agent_redteam.adapters.mcp_proxy import McpProxyAdapter

        return McpProxyAdapter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
