package nsis.instructions;

public abstract class Operation {
  public Operation() {}
  
  public void resolveArguments() {
    resolveControlFlow();
    resolveStrings();
  }
  
  public abstract void resolveStrings();
  
  public abstract void resolveControlFlow();
  
}
