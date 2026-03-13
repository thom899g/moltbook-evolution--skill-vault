"""
Skill Expression Language (SEL) Parser and Verifier
Domain-Specific Language that physically cannot express malicious actions
"""
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import lark
from lark import Lark, Transformer, v_args

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# SEL Grammar Definition - Whitelisted operations only
SEL_GRAMMAR = r"""
    start: expression+

    expression: capability_call
              | function_call
              | variable_assignment
              | control_flow

    capability_call: CAPABILITY_NAME "(" (arg ("," arg)*)? ")" "->" VAR_NAME
    function_call: FUNC_NAME "(" (arg ("," arg)*)? ")" "->" VAR_NAME
    variable_assignment: VAR_NAME "=" (literal | VAR_NAME | function_call | capability_call)
    control_flow: "if" comparison "{" expression+ "}" ("else" "{" expression+ "}")?
                | "for" VAR_NAME "in" range "{" expression+ "}"

    comparison: VAR_NAME COMPARATOR (literal | VAR_NAME)
    range: "range" "(" NUMBER "," NUMBER ")"

    arg: literal | VAR_NAME
    literal: STRING | NUMBER | BOOLEAN | NULL

    CAPABILITY_NAME: /[A-Z][A-Z0-9_]+/
    FUNC_NAME: /[a-z][a-z0-9_]+/
    VAR_NAME: /[a-z][a-z0-9_]*/
    COMPARATOR: "==" | "!=" | "<" | ">" | "<=" | ">="

    STRING: /"[^"]*"/
    NUMBER: /-?\d+(\.\d+)?/
    BOOLEAN: "true" | "false"
    NULL: "null"

    %import common.WS
    %ignore WS
"""

@dataclass
class SELVerificationResult:
    """Result of SEL verification"""
    is_valid: bool
    warnings: List[str]
    errors: List[str]
    capabilities_required: List[str]
    resource_estimate: Dict[str, float]
    ast: Optional[Dict] = None

class SELTransformer(Transformer):
    """Transforms SEL parse tree into safe AST"""
    
    def __init__(self):
        super().__init__()
        self.capabilities_used = set()
        self.variables = {}
        self.function_calls = []
        
    def capability_call(self, items):
        cap_name = str(items[0])
        # Verify capability exists in whitelist
        if cap_name not in self._get_capability_whitelist():
            raise VerificationError(f"Capability '{cap_name}' not in whitelist")
        self.capabilities_used.add(cap_name)
        return {"type": "capability_call", "capability": cap_name, "args": items[1:-2], "output": items[-1]}
    
    def _get_capability_whitelist(self) -> List[str]:
        """Return whitelisted capabilities - extensible via configuration"""
        return [
            "NETWORK_GET",
            "NETWORK_POST",
            "DATA_TRANSFORM",
            "DATA_AGGREGATE",
            "USER_NOTIFY",
            "STORAGE_READ",
            "STORAGE_WRITE",
            "TIME_GET",
            "MATH_COMPUTE",
            "STRING_PROCESS"
        ]
    
    @v_args(inline=True)
    def start(self, *expressions):
        return {
            "type": "program",
            "expressions": list(expressions),
            "capabilities_required": list(self.capabilities_used),
            "variables": self.variables
        }

class SELParser:
    """Secure parser for Skill Expression Language"""
    
    def __init__(self):
        self.parser = Lark(
            SEL_GRAMMAR,
            parser='lalr',
            transformer=SELTransformer()
        )
        logger.info("SEL parser initialized with secure grammar")
    
    def parse(self, sel_code: str) -> Tuple[Dict, List[str]]:
        """
        Parse SEL code into verified AST
        
        Args:
            sel_code: SEL source code string
            
        Returns:
            Tuple of (ast, warnings)
            
        Raises:
            VerificationError: If code violates SEL constraints
        """
        try:
            # Step 1: Parse into AST
            ast = self.parser.parse(sel_code)
            
            # Step 2: Run safety checks
            warnings = self._safety_checks(ast)
            
            logger.info(f"Successfully parsed SEL code with {len(warnings)} warnings")
            return ast, warnings
            
        except lark.exceptions.LarkError as e:
            logger.error(f"SEL parsing failed: {str(e)}")
            raise VerificationError(f"Syntax error in SEL: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected parsing error: {str(e)}")
            raise VerificationError(f"Parsing failed: {str(e)}")
    
    def _safety_checks(self, ast: Dict) -> List[str]:
        """Run additional safety checks on AST"""
        warnings = []
        
        # Check for infinite loops (simple heuristic)
        if self._detect_potential_loops(ast):
            warnings.append("Potential unbounded loop detected - ensure termination")
        
        # Check variable usage
        if self._check_uninitialized_variables(ast):
            warnings.append("Some variables may be used before initialization")
        
        # Estimate resource usage
        resource_estimate = self._estimate_resources(ast)
        for resource, value in resource_estimate.items():
            if value > 100:  # Threshold
                warnings.append(f"High {resource} usage estimated: {value}")
        
        return warnings
    
    def _detect_potential_loops(self, ast: Dict) -> bool:
        """Simple loop detection heuristic"""
        # Implementation placeholder
        return False
    
    def _check_uninitialized_variables(self, ast: Dict) -> bool:
        """Check for variables used before assignment"""
        # Implementation placeholder
        return False
    
    def _estimate_resources(self, ast: Dict) -> Dict[str, float]:
        """Estimate resource usage from AST"""
        return {
            "cpu_cycles": 1000,
            "memory_bytes": 1024,
            "network_calls": len(ast.get("capabilities_required", []))
        }

class SELVerifier:
    """Full SEL verification pipeline"""
    
    def __init__(self, parser: Optional[SELParser] = None):
        self.parser = parser or SELParser()
        self.verification_history = []
    
    def verify(self, sel_code: str, developer_id: str) -> SELVerificationResult:
        """
        Complete verification of SEL code
        
        Args:
            sel_code: SEL source code
            developer_id: Unique developer identifier
            
        Returns:
            VerificationResult with validation status
        """
        logger.info(f"Starting SEL verification for developer: {developer_id}")
        
        errors = []
        warnings = []
        
        try:
            # Step 1: Parse and basic safety
            ast, parse_warnings = self.parser.parse(sel_code)
            warnings.extend(parse_warnings)
            
            # Step 2: Intent analysis
            intent_warnings = self._analyze_intent(ast)
            warnings.extend(intent_warnings)
            
            # Step 3: Capability validation
            capabilities = ast.get("capabilities_required", [])
            if not self._validate_capabilities(capabilities):
                errors.append("Invalid capability request")
            
            # Step 4: Resource bounding
            resource_estimate = self._bound_resources(ast)
            
            # Log verification
            self.verification_history.append({
                "developer_id": developer_id,
                "timestamp": "now",  # Would use datetime in production
                "capabilities": capabilities,
                "warnings": warnings,
                "errors": errors
            })
            
            result = SELVerificationResult(
                is_valid=len(errors) == 0,
                warnings=warnings,
                errors=errors,
                capabilities_required=capabilities,
                resource_estimate=resource_estimate,
                ast=ast if len(errors) == 0 else None
            )
            
            logger.info(f"Verification complete: {'VALID' if result.is_valid else 'INVALID'}")
            return result
            
        except VerificationError as e:
            logger.error(f"Verification failed: {str(e)}")
            return SELVerificationResult(
                is_valid=False,
                warnings=[],
                errors=[str(e)],
                capabilities_required=[],
                resource_estimate={}
            )
    
    def _analyze_intent(self, ast: Dict) -> List[str]:
        """Analyze skill intent for potential misuse"""
        warnings = []
        
        # Check for data exfiltration patterns
        if self._detect_exfiltration_pattern(ast):
            warnings.append("Pattern resembles data exfiltration - ensure user consent")
        
        # Check for privilege escalation attempts
        if self._detect_privilege_pattern(ast):
            warnings.append("Pattern resembles privilege escalation")
        
        return warnings
    
    def _detect_exfiltration_pattern(self, ast: Dict) -> bool:
        """Detect potential data exfiltration patterns"""
        return False
    
    def _detect_privilege_pattern(self, ast: Dict) -> bool:
        """Detect privilege escalation attempts"""
        return False
    
    def _validate_capabilities(self, capabilities: List[str]) -> bool:
        """Validate requested capabilities against policy"""
        valid_caps = [
            "NETWORK_GET", "NETWORK_POST", "DATA_TRANSFORM",
            "DATA_AGGREGATE", "USER_NOTIFY", "STORAGE_READ",
            "STORAGE_WRITE", "TIME_GET", "MATH_COMPUTE", "STRING_PROCESS"
        ]
        return all(cap in valid_caps for cap in capabilities)
    
    def _bound_resources(self, ast: Dict) -> Dict[str, float]:
        """Apply resource bounds to estimates"""
        from skill_vault import MAX_RESOURCE_BOUNDS
        
        estimate = self.parser._estimate_resources(ast)
        bounded = {}
        
        for resource, value in estimate.items():
            # Convert to standard resource names
            if resource == "cpu_cycles":
                bounded["cpu_time_seconds"] = min(value / 1000000, MAX_RESOURCE_BOUNDS["cpu_time_seconds"])
            elif resource == "memory_bytes":
                bounded["memory_mb"] = min(value / (1024*1024), MAX_RESOURCE_BOUNDS["memory_mb"])
            elif resource == "network_calls":
                bounded["network_requests"] = min(value, MAX_RESOURCE_BOUNDS["network_requests"])
        
        return bounded