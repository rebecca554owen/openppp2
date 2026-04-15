# Documentation Index

[中文版本](README_CN.md)

This directory serves as the comprehensive documentation center for OPENPPP2, a sophisticated network tunneling and routing system designed for modern cross-platform deployment scenarios. The documentation set provided here is intentionally structured in multiple layers, reflecting the inherent complexity of the OPENPPP2 architecture itself. Understanding why this layered approach was chosen is essential for navigating the documentation effectively and gaining a proper understanding of the system as a whole.

OPENPPP2 is not a single-purpose tool or a monolithic application with one well-defined function. Instead, it represents an integrated suite of technologies that combine multiple functional domains into a cohesive system capable of addressing diverse networking requirements. The system simultaneously encompasses protected transport mechanisms that secure data in transit, tunnel action protocols that define how tunnel endpoints communicate and coordinate, client-side host integration that seamlessly injects the tunneling capability into endpoint systems, and server-side session switching and forwarding logic that intelligently routes traffic through the tunnel infrastructure. Additionally, OPENPPP2 provides sophisticated route and DNS steering capabilities that give operators fine-grained control over how traffic flows through the system, optional static packet and MUX paths that enable optimized routing for specific use cases, platform-specific host networking behaviors that ensure proper operation across different operating systems, and an optional external management backend that enables centralized control and monitoring of deployed instances.

Because OPENPPP2 combines all of these capabilities into a single system, the documentation must necessarily reflect this layered architecture. Attempting to understand the system by reading individual files in isolation would be confusing and ineffective, as each file addresses a specific layer or aspect of the system. The most useful approach to reading the documentation is therefore to follow curated reading paths that guide you through the material in a logical order, building your understanding progressively from foundational concepts to advanced topics. This index document provides those curated paths, organized by common use cases and learning objectives.

## Reading Paths

OPENPPP2 is a complex system with many interconnected components. Rather than forcing you to figure out the best order to read the documentation yourself, we have organized the material into three primary reading paths, each designed for a specific audience or learning objective. Choose the path that most closely matches your goals and experience level.

### Understanding The Whole System

This path is designed for readers who want to develop a comprehensive understanding of OPENPPP2 from the ground up. It starts with the highest-level overview and progressively dives deeper into each component, building a complete mental model of how the system works. This path is ideal for architects, technical leads, and anyone who needs to make decisions about how to deploy or extend OPENPPP2.

1. [`../README.md`](../README.md) - The project root README provides the highest-level introduction to OPENPPP2, including the project's mission, key capabilities, and basic概念 of what the system accomplishes. It also contains important information about licensing, building, and getting started that is essential before diving into the detailed technical documentation.

2. [`ENGINEERING_CONCEPTS.md`](ENGINEERING_CONCEPTS.md) - This document articulates the engineering philosophy behind OPENPPP2, explaining the design decisions and architectural principles that guided the system's development. It introduces the specialized vocabulary used throughout the documentation, ensuring that you can understand the precise meaning of technical terms as they are used in subsequent documents. The engineering concepts document is critical reading because it establishes the conceptual foundation upon which all other documentation builds.

3. [`ARCHITECTURE.md`](ARCHITECTURE.md) - The architecture document provides a top-level view of the entire OPENPPP2 system, mapping out the major components, their boundaries, and the relationships between them. It describes the main roles within the system (client and server), the different planes of operation (control plane, data plane, management plane), and the key interfaces between components. Understanding the architecture is essential for understanding how the individual components fit together into a cohesive system.

4. [`STARTUP_AND_LIFECYCLE.md`](STARTUP_AND_LIFECYCLE.md) - This document details the startup sequence, explaining how OPENPPP2 initializes, selects its role (client or server), prepares its environment, runs its main processing loop (the tick loop), and handles shutdown gracefully. Understanding the lifecycle is important for debugging startup issues, understanding resource allocation patterns, and properly integrating OPENPPP2 with system startup procedures.

5. [`TRANSMISSION.md`](TRANSMISSION.md) - The transmission document covers the protected transport layer, explaining how data is framed, encrypted, and transmitted between client and server. It describes the cipher layering approach, the runtime transport model, and how the system handles different network conditions. This document is essential for understanding the security and reliability characteristics of OPENPPP2.

6. [`HANDSHAKE_SEQUENCE.md`](HANDSHAKE_SEQUENCE.md) - This document explains the actual handshake process that occurs when a client connects to a server, including the order of operations, key exchange mechanisms, and how session keys are derived. Understanding the handshake sequence is important for troubleshooting connection issues and understanding the security properties of established sessions.

7. [`PACKET_FORMATS.md`](PACKET_FORMATS.md) - The packet formats document provides detailed specifications for all packet structures used by OPENPPP2, including the static packet format that ensures compatibility across versions and the wire-level framing that defines how bytes are organized on the network. This document is the definitive reference for anyone implementing clients, servers, or analysis tools.

8. [`CLIENT_ARCHITECTURE.md`](CLIENT_ARCHITECTURE.md) - This document explores the client-side runtime architecture in detail, covering the switcher that determines how traffic is routed, the exchanger that handles protocol translation, routing logic, DNS resolution, proxy integration, address mapping, MUX (multiplexing) behavior, static path routing, and managed IPv6 support. Understanding the client architecture is essential for deploying clients in complex network environments.

9. [`SERVER_ARCHITECTURE.md`](SERVER_ARCHITECTURE.md) - The server architecture document covers the server-side components, including acceptors that listen for incoming connections, session switching logic that routes traffic to appropriate backends, forwarding mechanisms, mapping configurations, static path support, IPv6 capabilities, and backend cooperation protocols. This document is essential for deploying and operating OPENPPP2 servers.

10. [`ROUTING_AND_DNS.md`](ROUTING_AND_DNS.md) - This document explains the route steering capabilities of OPENPPP2, including how traffic is routed based on configurable rules, bypass mechanisms that allow certain traffic to avoid the tunnel, DNS redirect functionality that enables DNS-based filtering and optimization, namespace caching that improves performance, and vBGP-style route inputs that enable sophisticated routing policies. Understanding routing and DNS is critical for achieving the desired traffic flow patterns in your deployment.

11. [`PLATFORMS.md`](PLATFORMS.md) - The platforms document covers the platform-specific host integration differences across Windows, Linux, macOS, and Android. Each platform has unique requirements and capabilities for network integration, and this document explains how OPENPPP2 adapts to each environment. Understanding platform differences is essential for cross-platform deployment and troubleshooting.

12. [`DEPLOYMENT.md`](DEPLOYMENT.md) - The deployment document provides practical guidance for deploying OPENPPP2 in production environments, including host requirements, network architecture considerations, optional backend deployment, and Linux IPv6 server prerequisites. This document bridges the gap between understanding the system and actually deploying it.

13. [`OPERATIONS.md`](OPERATIONS.md) - The operations document covers runtime operations including observability (logging, metrics, tracing), restart logic and recovery procedures, cleanup procedures for temporary resources, failure classification and handling, and troubleshooting methodology. This document is essential for operating OPENPPP2 reliably in production.

### Reading The Code Efficiently

This path is designed for developers who need to understand the codebase to implement features, fix bugs, or integrate OPENPPP2 with other systems. It focuses on the most important source files and their relationships, providing a pragmatic roadmap for navigating the code. This path assumes you are comfortable reading C++ code and understanding network protocols.

1. [`SOURCE_READING_GUIDE.md`](SOURCE_READING_GUIDE.md) - This document provides a curated guide for reading the OPENPPP2 source code, suggesting the most effective order to explore the codebase based on your specific goals. It identifies key files and explains their purposes, helping you focus your attention on the most relevant code for your task.

2. [`ARCHITECTURE.md`](ARCHITECTURE.md) - Understanding the system architecture is prerequisite to understanding the code. This document provides the conceptual framework that makes the code meaningful. Do not skip this document even if you are eager to start reading code.

3. [`TRANSMISSION.md`](TRANSMISSION.md) - The transmission layer is the heart of OPENPPP2's functionality. Understanding how data is transmitted, encrypted, and received is essential for understanding the core data flow through the system.

4. [`LINKLAYER_PROTOCOL.md`](LINKLAYER_PROTOCOL.md) - The linklayer protocol defines the vocabulary of tunnel actions that clients and servers use to coordinate. Understanding this protocol is essential for understanding how the client and server interact at the protocol level.

5. `main.cpp` - The main entry point provides the starting point for understanding how the system initializes and coordinates its components. From here you can trace the initialization sequence and understand how the different subsystems are brought online.

6. `ppp/configurations/*` - The configuration subsystem handles loading, parsing, and validating configuration files. Understanding how configuration works is essential for customizing OPENPPP2 behavior.

7. `ppp/transmissions/*` - The transmission implementations contain the core logic for protected transport. These files are where the actual data processing happens.

8. `ppp/app/protocol/*` - The protocol implementations define the tunnel action protocol and related message handling. These files define the semantics of communication between client and server.

9. `ppp/app/client/*` - The client implementations contain the client-side runtime logic, including routing, DNS handling, and session management. Understanding these files is essential for client-side development.

10. `ppp/app/server/*` - The server implementations contain the server-side runtime logic, including connection handling, forwarding, and backend integration. Understanding these files is essential for server-side development.

11. Platform directories - The platform-specific code is organized in separate directories for each supported platform. These contain the code that adapts OPENPPP2 to each operating system's networking stack and system APIs.

12. `go/*` - The Go management backend contains the optional backend service for centralized management. This is only relevant for deployments that use the managed deployment model.

### Focus On Deployment And Runtime

This path is designed for operators and DevOps engineers who need to deploy and manage OPENPPP2 in production. It focuses on practical information needed for day-to-day operations, skipping theoretical background in favor of actionable guidance. If your primary goal is to get OPENPPP2 running and keep it running, start here.

1. [`CONFIGURATION.md`](CONFIGURATION.md) - The configuration reference explains all configuration options, their default values, how values are normalized, and the key fields that most commonly need adjustment. This document is your primary reference when configuring OPENPPP2.

2. [`CLI_REFERENCE.md`](CLI_REFERENCE.md) - The command-line interface reference documents all command-line arguments, organized by category (common arguments, role-specific arguments, platform-specific arguments). This document tells you what options are available and how to use them.

3. [`PLATFORMS.md`](PLATFORMS.md) - Understanding platform differences is essential for successful deployment. This document explains what you need to know about each supported platform to deploy OPENPPP2 correctly.

4. [`ROUTING_AND_DNS.md`](ROUTING_AND_DNS.md) - Routing configuration is often the most complex part of an OPENPPP2 deployment. This document explains the routing and DNS capabilities in practical terms, with examples for common scenarios.

5. [`DEPLOYMENT.md`](DEPLOYMENT.md) - The deployment guide provides step-by-step instructions for deploying OPENPPP2 in various configurations, including host requirements, network architecture, and optional component deployment.

6. [`OPERATIONS.md`](OPERATIONS.md) - The operations guide covers day-to-day operational tasks including monitoring, troubleshooting, backup and recovery, and upgrade procedures.

7. [`SECURITY.md`](SECURITY.md) - The security document provides guidance on hardening OPENPPP2 deployments, understanding the security model, and implementing appropriate access controls.

## Document Map

The documentation is organized into several logical sections, each addressing a particular aspect of OPENPPP2. This map provides a quick reference to locate the document you need, grouped by topic area.

### Foundation

These documents establish the conceptual foundation for understanding OPENPPP2. If you are new to OPENPPP2, start here before exploring other documentation.

- [`ENGINEERING_CONCEPTS.md`](ENGINEERING_CONCEPTS.md): This document explains the engineering stance and system intent behind OPENPPP2. It describes the problems that OPENPPP2 was designed to solve, the design principles that guided its development, and the tradeoffs that were made in the implementation. Additionally, this document defines the specialized vocabulary used throughout the documentation, ensuring consistent understanding of technical terms. The engineering concepts document is essential reading for anyone who needs to make informed decisions about using or extending OPENPPP2.

- [`ARCHITECTURE.md`](ARCHITECTURE.md): The architecture document provides a top-level view of the OPENPPP2 system, mapping out the major components, their boundaries, and the relationships between them. It describes the main roles within the system (client and server), the different planes of operation (control plane, data plane, management plane), and the key interfaces between components. The architecture document uses diagrams and textual explanations to convey the system's structure in an accessible way.

- [`STARTUP_AND_LIFECYCLE.md`](STARTUP_AND_LIFECYCLE.md): This document details the complete startup sequence, from the initial program entry point through role selection, environment preparation, the main processing loop (tick loop), and graceful shutdown. Understanding the lifecycle is important for debugging startup issues, understanding when and how resources are allocated, and properly integrating OPENPPP2 with system startup and shutdown procedures.

### Transport And Protocol

These documents cover the transport layer and protocol specifications that enable secure communication between OPENPPP2 clients and servers.

- [`TRANSMISSION.md`](TRANSMISSION.md): The transmission document explains the protected transport mechanisms, including framing (how data is organized into transmitable units), cipher layering (how encryption is applied), and the runtime transport model (how the system handles network conditions). This document describes both the theoretical foundations and the practical implementation details.

- [`HANDSHAKE_SEQUENCE.md`](HANDSHAKE_SEQUENCE.md): The handshake sequence document explains the exact order of operations when a client connects to a server, including how keys are exchanged, how session keys are derived, and how the connection state is established. Understanding the handshake sequence is essential for troubleshooting connection failures and understanding the security properties of established sessions.

- [`PACKET_FORMATS.md`](PACKET_FORMATS.md): The packet formats document provides complete specifications for all packet structures used by OPENPPP2. It covers the static packet format that ensures compatibility across different versions, the wire-level framing that defines byte organization on the network, and the meaning of each field in every packet type. This document is the authoritative reference for protocol implementation.

- [`TRANSMISSION_PACK_SESSIONID.md`](TRANSMISSION_PACK_SESSIONID.md): This document explains how session identity is encoded and transmitted, including the control-plane semantics (what the session ID means to the protocol) and the information-envelope context (how the session ID is wrapped in the transmission). Session IDs are fundamental to the operation of the protocol.

- [`LINKLAYER_PROTOCOL.md`](LINKLAYER_PROTOCOL.md): The linklayer protocol document defines the vocabulary of tunnel actions that clients and servers use to coordinate. It explains the meaning of each action, when actions are sent, and how actions affect the tunnel state. This is the protocol that enables the client and server to work together.

- [`SECURITY.md`](SECURITY.md): The security document addresses the trust boundaries within OPENPPP2, the enforcement points where security policy is applied, realistic security claims (what security properties the system provides and what it does not), and hardening guidance (how to configure the system for higher security). Understanding security is essential for deploying OPENPPP2 in security-sensitive environments.

### Runtime

These documents describe the runtime behavior of OPENPPP2 clients and servers, explaining how the system processes traffic and manages sessions.

- [`CLIENT_ARCHITECTURE.md`](CLIENT_ARCHITECTURE.md): The client architecture document provides a detailed exploration of the client-side runtime, covering the switcher (which determines how incoming traffic is routed), exchanger (which handles protocol translation between different network conventions), routes (which define traffic routing policies), DNS (which handles DNS resolution and optionally DNS-based filtering), proxies (which enable integration with upstream proxy servers), mappings (which translate addresses between different namespaces), MUX (which enables multiplexing of multiple connections over a single tunnel), static path (which provides alternative routing for specific traffic patterns), and managed IPv6 (which handles IPv6 deployment in managed environments). This document is essential for deploying and configuring clients.

- [`SERVER_ARCHITECTURE.md`](SERVER_ARCHITECTURE.md): The server architecture document covers the server-side runtime in detail, explaining acceptors (which listen for and accept incoming connections), session switch (which routes sessions to appropriate backends), forwarding (which moves traffic between client connections and backend destinations), mappings (which translate addresses), static path (which provides alternative routing), IPv6 (which handles IPv6 traffic), and backend cooperation (which enables communication with external systems). This document is essential for deploying and operating servers.

- [`ROUTING_AND_DNS.md`](ROUTING_AND_DNS.md): The routing and DNS document explains how OPENPPP2 steers traffic based on configurable rules, including route steering (directing traffic based on destination, source, or other criteria), bypass (allowing certain traffic to avoid the tunnel entirely), DNS redirect (intercepting and redirecting DNS queries for filtering or optimization), namespace cache (caching DNS results for performance), and vBGP-style route inputs (enabling BGP-based routing policies). This document provides both conceptual explanations and practical configuration examples.

### Platform And Management

These documents address platform-specific considerations and optional management components.

- [`PLATFORMS.md`](PLATFORMS.md): The platforms document explains the differences in host integration across Windows, Linux, macOS, and Android. Each platform has unique requirements for network stack integration, system permissions, and API availability. This document explains how OPENPPP2 adapts to each platform and what configuration options are available for each.

- [`MANAGEMENT_BACKEND.md`](MANAGEMENT_BACKEND.md): The management backend document explains the optional Go-based backend service that enables centralized management of OPENPPP2 deployments. It describes the backend's role in the system, its dependencies, the APIs it exposes, and the interaction model between the core OPENPPP2 components and the backend. This document is relevant for deployments that use the managed deployment model.

### Configuration, Usage, And Operations

These documents provide practical guidance for configuring, using, and operating OPENPPP2 in production environments.

- [`CONFIGURATION.md`](CONFIGURATION.md): The configuration document explains the configuration model in detail, including the structure of configuration files, default values for all options, the normalization logic that processes configuration values, and the key fields that most commonly require adjustment. This document is the primary reference for configuring OPENPPP2.

- [`CLI_REFERENCE.md`](CLI_REFERENCE.md): The CLI reference documents all command-line arguments supported by OPENPPP2, organized into logical groups: common arguments (available in all modes), role-specific arguments (client-only or server-only), and platform-specific arguments (available only on certain platforms). Each argument is documented with its purpose, syntax, and default value.

- [`USER_MANUAL.md`](USER_MANUAL.md): The user manual is an operator-focused guide that explains how to use OPENPPP2 in common scenarios. It provides step-by-step instructions for typical tasks, practical examples for common configurations, and troubleshooting guidance for frequently encountered issues.

- [`DEPLOYMENT.md`](DEPLOYMENT.md): The deployment document provides comprehensive guidance for deploying OPENPPP2 in production. It covers the deployment model (how components are organized), host requirements (minimum and recommended specifications for different deployment scales), optional backend deployment (how to deploy the management backend if used), and Linux IPv6 server prerequisites (requirements for IPv6 support on Linux). This document bridges the gap between understanding the system and actually deploying it.

- [`OPERATIONS.md`](OPERATIONS.md): The operations document covers all aspects of running OPENPPP2 in production, including observability (how to monitor the system's health and performance), restart logic (how the system recovers from failures), cleanup (how to properly release resources), failure classification (understanding different failure modes and their appropriate responses), and troubleshooting order (a systematic approach to diagnosing and resolving problems).

- [`SOURCE_READING_GUIDE.md`](SOURCE_READING_GUIDE.md): The source reading guide provides practical guidance for developers who need to understand the OPENPPP2 codebase. It suggests an effective order for reading source files based on common development goals, identifies key files and their purposes, and explains the relationships between different parts of the code.

## Reading Principle

When reading OPENPPP2 documentation, it is essential to keep the system's layered architecture clearly in mind. Each layer addresses a different aspect of the system's functionality, and understanding each layer independently is crucial before attempting to understand how the layers interact. Attempting to understand all layers simultaneously typically leads to confusion and misunderstanding.

The layers that must be kept separate are:

- **Carrier transport**: The lowest layer handles the physical transmission of data over the network. This includes the raw socket operations, transport protocol (TCP/UDP) handling, and network address resolution. Understanding carrier transport is important for diagnosing network connectivity issues.

- **Protected transmission and handshake**: The next layer adds security to the carrier transport through encryption and key exchange. This layer ensures that data cannot be read or modified by unauthorized parties and that sessions are properly authenticated. Understanding protected transmission is important for security-related troubleshooting.

- **Tunnel action protocol**: Above the transmission layer, the tunnel action protocol defines the vocabulary of messages that clients and servers use to coordinate their behavior. This protocol enables the establishment, maintenance, and teardown of tunnels, as well as the transmission of tunneled traffic. Understanding the tunnel protocol is essential for understanding how clients and servers interact.

- **Client or server runtime behavior**: The runtime layer implements the application-level logic that distinguishes clients from servers. This includes routing decisions, session management, DNS resolution, and integration with the host system. Understanding runtime behavior is essential for deployment and configuration.

- **Platform-specific host integration**: The platform layer contains the code that adapts OPENPPP2 to each supported operating system. This includes network stack integration, system API calls, and platform-specific configuration. Understanding platform differences is important for cross-platform deployment.

- **Optional management backend**: The management backend layer (when deployed) provides centralized control and monitoring capabilities. This layer is optional and operates separately from the core OPENPPP2 components. Understanding the management backend is only relevant for deployments that use it.

Most confusion that arises when learning OPENPPP2 comes from mixing these layers together. For example, a problem that appears to be a routing issue might actually be a platform-specific network integration problem, or a security concern might actually be a configuration issue in the management backend. By keeping these layers separate and understanding each one independently, you can more accurately diagnose issues and make better-informed decisions about deployment and configuration.

This documentation set is designed to help you build a correct mental model of OPENPPP2 by presenting each layer in isolation before explaining how the layers interact. We encourage you to follow the reading paths provided in this document, starting with the path that best matches your background and goals. As you progress through the documentation, you will find that each document builds upon the previous ones, creating a comprehensive understanding of the system as a whole.