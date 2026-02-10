#!/usr/bin/env bash
# Generate protobuf Python stubs for all services
set -e

PROTO_DIR="proto"
SERVICES=("alert_ingestion" "incident_management" "oncall_service")

for svc in "${SERVICES[@]}"; do
    OUT_DIR="services/${svc}/generated"
    mkdir -p "$OUT_DIR"
    
    echo "Generating stubs for ${svc}..."
    python -m grpc_tools.protoc \
        -I"${PROTO_DIR}" \
        --python_out="${OUT_DIR}" \
        --grpc_python_out="${OUT_DIR}" \
        "${PROTO_DIR}/incidents.proto"
    
    # Fix relative imports in generated gRPC file
    sed -i 's/import incidents_pb2/from . import incidents_pb2/' "${OUT_DIR}/incidents_pb2_grpc.py"
    
    # Ensure __init__.py exists
    touch "${OUT_DIR}/__init__.py"
done

echo "All protobuf stubs generated successfully."
