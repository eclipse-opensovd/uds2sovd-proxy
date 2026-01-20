flowchart TD

%% -------------------------
%% Minimal POC (TCP only)
%% -------------------------
subgraph POC_Minimal["Minimal POC — TCP Only (Implemented)"]
    A[UDS Tester]
    B[DoIP Server]

    A -->|1. TCP Connect\n(port 13400)| B
    A -->|2. Routing Activation Request\n(DoIP, TCP)| B
    B -->|3. Routing Activation Response\n(DoIP, TCP)| A
    A -->|4. Diagnostic Message\n(UDS inside DoIP, TCP)| B
    B -->|5. Diagnostic Response\n(DoIP, TCP)| A
end

%% -------------------------
%% Production Flow (With UDP)
%% -------------------------
subgraph Production["Production Flow — With UDP (Implemented)"]
    C[UDS Tester]
    D[DoIP Server]

    C -->|1. Vehicle Identification Request\n(DoIP, UDP)| D
    D -->|2. Vehicle Identification Response\n(DoIP, UDP)| C
    C -->|3. TCP Connect\n(port 13400)| D
    C -->|4. Routing Activation Request\n(DoIP, TCP)| D
    D -->|5. Routing Activation Response\n(DoIP, TCP)| C
    C -->|6. Diagnostic Message\n(UDS inside DoIP, TCP)| D
    D -->|7. Diagnostic Response\n(DoIP, TCP)| C
end
