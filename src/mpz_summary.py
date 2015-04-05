import lldb

def mpz_summary (value,unused):
	if value == None or value.IsValid() == False:
		return "<invalid>"

	expr = "(char*) __gmpz_get_str(0, 10, %s)" % value.GetName()
	expr_value  = value.target.EvaluateExpression(expr,lldb.SBExpressionOptions())
	expr_str = expr_value.GetSummary()
	free_expr = "(void) free(%s)" % expr_value.GetName()
	return "%s" % expr_str

def __lldb_init_module(debugger, unused):
	debugger.HandleCommand("type summary add mpz_t --python-function mpz_summary.mpz_summary")
