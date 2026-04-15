from agent_redteam.adapters.callable import CallableAdapter

__all__ = [
    "CallableAdapter",
    "LLMAdapter",
    "LangChainAdapter",
    "OpenAIAgentsAdapter",
    "McpProxyAdapter",
    "HttpAdapter",
    "wrap_tools_with_canaries",
    "wrap_langchain_tools",
    "wrap_openai_agent_tools",
    "wrap_callable_tools",
    "CanaryInjector",
]


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
    if name == "HttpAdapter":
        from agent_redteam.adapters.http import HttpAdapter

        return HttpAdapter
    if name in ("wrap_tools_with_canaries", "wrap_langchain_tools"):
        from agent_redteam.adapters.canary_wrapper import wrap_langchain_tools

        return wrap_langchain_tools
    if name == "wrap_openai_agent_tools":
        from agent_redteam.adapters.canary_wrapper import wrap_openai_agent_tools

        return wrap_openai_agent_tools
    if name == "wrap_callable_tools":
        from agent_redteam.adapters.canary_wrapper import wrap_callable_tools

        return wrap_callable_tools
    if name == "CanaryInjector":
        from agent_redteam.adapters.canary_wrapper import CanaryInjector

        return CanaryInjector
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
