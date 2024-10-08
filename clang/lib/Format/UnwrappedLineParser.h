//===--- UnwrappedLineParser.h - Format C++ code ----------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file contains the declaration of the UnwrappedLineParser,
/// which turns a stream of tokens into UnwrappedLines.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_LIB_FORMAT_UNWRAPPEDLINEPARSER_H
#define LLVM_CLANG_LIB_FORMAT_UNWRAPPEDLINEPARSER_H

#include "Macros.h"
#include <stack>
#include <variant>
#include <vector>

namespace clang {
namespace format {

struct UnwrappedLineNode;

/// An unwrapped line is a sequence of \c Token, that we would like to
/// put on a single line if there was no column limit.
///
/// This is used as a main interface between the \c UnwrappedLineParser and the
/// \c UnwrappedLineFormatter. The key property is that changing the formatting
/// within an unwrapped line does not affect any other unwrapped lines.
struct UnwrappedLine {
  UnwrappedLine() = default;

  /// The \c Tokens comprising this \c UnwrappedLine.
  std::list<UnwrappedLineNode> Tokens;

  /// The indent level of the \c UnwrappedLine.
  unsigned Level = 0;

  /// The \c PPBranchLevel (adjusted for header guards) if this line is a
  /// \c InMacroBody line, and 0 otherwise.
  unsigned PPLevel = 0;

  /// Whether this \c UnwrappedLine is part of a preprocessor directive.
  bool InPPDirective = false;
  /// Whether this \c UnwrappedLine is part of a pramga directive.
  bool InPragmaDirective = false;
  /// Whether it is part of a macro body.
  bool InMacroBody = false;
  /// Whether it is part of a Cpp2 declaration.
  bool InCpp2Declaration = false;

  /// Nesting level of unbraced body of a control statement.
  unsigned UnbracedBodyLevel = 0;

  bool MustBeDeclaration = false;

  /// Whether the parser has seen \c decltype(auto) in this line.
  bool SeenDecltypeAuto = false;

  /// \c True if this line should be indented by ContinuationIndent in
  /// addition to the normal indention level.
  bool IsContinuation = false;

  /// If this \c UnwrappedLine closes a block in a sequence of lines,
  /// \c MatchingOpeningBlockLineIndex stores the index of the corresponding
  /// opening line. Otherwise, \c MatchingOpeningBlockLineIndex must be
  /// \c kInvalidIndex.
  size_t MatchingOpeningBlockLineIndex = kInvalidIndex;

  /// If this \c UnwrappedLine opens a block, stores the index of the
  /// line with the corresponding closing brace.
  size_t MatchingClosingBlockLineIndex = kInvalidIndex;

  static const size_t kInvalidIndex = -1;

  unsigned FirstStartColumn = 0;
};

/// Interface for users of the UnwrappedLineParser to receive the parsed lines.
/// Parsing a single snippet of code can lead to multiple runs, where each
/// run is a coherent view of the file.
///
/// For example, different runs are generated:
/// - for different combinations of #if blocks
/// - when macros are involved, for the expanded code and the as-written code
///
/// Some tokens will only be visible in a subset of the runs.
/// For each run, \c UnwrappedLineParser will call \c consumeUnwrappedLine
/// for each parsed unwrapped line, and then \c finishRun to indicate
/// that the set of unwrapped lines before is one coherent view of the
/// code snippet to be formatted.
class UnwrappedLineConsumer {
public:
  virtual ~UnwrappedLineConsumer() {}
  virtual void consumeUnwrappedLine(const UnwrappedLine &Line) = 0;
  virtual void finishRun() = 0;
};

class FormatTokenSource;

class UnwrappedLineParser {
public:
  UnwrappedLineParser(SourceManager &SourceMgr, const FormatStyle &Style,
                      const AdditionalKeywords &Keywords,
                      unsigned FirstStartColumn, ArrayRef<FormatToken *> Tokens,
                      UnwrappedLineConsumer &Callback,
                      llvm::SpecificBumpPtrAllocator<FormatToken> &Allocator,
                      IdentifierTable &IdentTable);

  void parse();

private:
  enum class IfStmtKind {
    NotIf,   // Not an if statement.
    IfOnly,  // An if statement without the else clause.
    IfElse,  // An if statement followed by else but not else if.
    IfElseIf // An if statement followed by else if.
  };

  void reset();
  void parseFile();
  bool precededByCommentOrPPDirective() const;
  bool parseLevel(const FormatToken *OpeningBrace = nullptr,
                  IfStmtKind *IfKind = nullptr,
                  FormatToken **IfLeftBrace = nullptr);
  bool mightFitOnOneLine(UnwrappedLine &Line,
                         const FormatToken *OpeningBrace = nullptr) const;
  FormatToken *parseBlock(bool MustBeDeclaration = false,
                          unsigned AddLevels = 1u, bool MunchSemi = true,
                          bool KeepBraces = true, IfStmtKind *IfKind = nullptr,
                          bool UnindentWhitesmithsBraces = false);
  void parseChildBlock();
  void parsePPDirective();
  void parsePPDefine();
  void parsePPIf(bool IfDef);
  void parsePPElse();
  void parsePPEndIf();
  void parsePPPragma();
  void parsePPUnknown();
  void readTokenWithJavaScriptASI();
  void parseStructuralElement(const FormatToken *OpeningBrace = nullptr,
                              IfStmtKind *IfKind = nullptr,
                              FormatToken **IfLeftBrace = nullptr,
                              bool *HasDoWhile = nullptr,
                              bool *HasLabel = nullptr);
  bool tryToParseBracedList();
  bool parseBracedList(bool IsAngleBracket = false, bool IsEnum = false);
  bool parseParens(TokenType AmpAmpTokenType = TT_Unknown);
  void parseSquare(bool LambdaIntroducer = false);
  void keepAncestorBraces();
  void parseUnbracedBody(bool CheckEOF = false);
  void handleAttributes();
  bool handleCppAttributes();
  bool isBlockBegin(const FormatToken &Tok) const;
  FormatToken *parseIfThenElse(IfStmtKind *IfKind, bool KeepBraces = false,
                               bool IsVerilogAssert = false);
  void parseTryCatch();
  void parseLoopBody(bool KeepBraces, bool WrapRightBrace);
  void parseForOrWhileLoop(bool HasParens = true);
  void parseDoWhile();
  void parseLabel(bool LeftAlignLabel = false);
  void parseCaseLabel();
  void parseSwitch(bool IsExpr);
  void parseNamespace();
  bool parseModuleImport();
  void parseNew();
  void parseAccessSpecifier();
  bool parseEnum();
  bool parseStructLike();
  bool parseRequires();
  void parseRequiresClause(FormatToken *RequiresToken);
  void parseRequiresExpression(FormatToken *RequiresToken);
  void parseConstraintExpression();
  class Cpp2FormatTokenSource;
  /// \pre The last result of \c Tokens->getNextToken().
  using CurrentToken = const FormatToken *;
  template <CurrentToken (*Increment)(FormatTokenSource *)>
  struct CurrentTokenIterator;
  using Cpp2AtFunction = bool (UnwrappedLineParser::*)(CurrentToken) const;
  using Cpp2ParserFunction = void (UnwrappedLineParser::*)();
  class Cpp2ParseContext {
  private:
    enum class C : unsigned char {
      DeclOrStmt,  // `{ ... }` is a block. Otherwise, it's a child block.
      TempArgList, // `< > <= >= << >> <<= >>=` are not operators.
                   // Otherwise, they are operators.
      SomethingElse
    } Context = C::DeclOrStmt;

  public:
    auto stackDeclarationOrStatement();
    auto stackTemplateArgumentList();
    auto stackSomethingElse();
    bool isDeclarationOrStatement() const { return Context == C::DeclOrStmt; }
    bool isTemplateArgumentList() const { return Context == C::TempArgList; }

  private:
    Cpp2ParserFunction Parser = nullptr;

  public:
    auto stack(Cpp2ParserFunction);
    Cpp2ParserFunction getParser() const { return Parser; }
  };
  struct Cpp2Punctuator {
    tok::TokenKind Kind = tok::unknown;
    TokenType Type = TT_Unknown;
  };
  struct Cpp2ParsedDeclarationSignature {
    bool HasFunctionType = false;
    bool ParsedInitializer = false;
  };
  enum class Cpp2ListOf {
    NotAList,
    Undecided, // Could be declarations or expressions.
    Expressions,
    Declarations
  };
  using Cpp2TokenToParse =
      std::variant<tok::TokenKind, const IdentifierInfo *, Cpp2AtFunction>;
  Cpp2ParseContext Cpp2Context;
  bool parseCpp2Token(Cpp2TokenToParse, TokenType = TT_Unknown);
  bool parseCpp2Token(ArrayRef<Cpp2TokenToParse>, TokenType = TT_Unknown);
  bool parsesCpp2(Cpp2ParserFunction);
  auto setupCpp2BalancedPunctuatorsFormatting(TokenType, tok::TokenKind);
  void parseCpp2BalancedPunctuators(Cpp2Punctuator Opener, Cpp2ParserFunction);
  void parseCpp2Until(tok::TokenKind, Cpp2ParserFunction);
  void parseCpp2BlockBody();
  bool parsingCpp2ImplicitBlock() const;
  void parseCpp2Block(Cpp2ParserFunction);
  template <Cpp2ParserFunction> void parseCommaSeparatedCpp2();
  void parseCpp2DeclarationColon();
  void parseCpp2Semi();
  void parseCpp2Literal();
  void parseCpp2MultiTokenType();
  bool isCpp2SingleTokenOperator(CurrentToken) const;
  int atCpp2IdentifierTokens(CurrentToken);
  bool parseCpp2Identifier();
  void parseCpp2TypeQualifierSeq();
  void parseCpp2TypeId();
  void parseCpp2TemplateArgument();
  bool atCpp2TemplateArgumentList(CurrentToken);
  void parseCpp2TemplateArgumentList();
  void parseCpp2UnqualifiedId();
  void parseCpp2IdExpression();
  void parseCpp2ExpressionList();
  void parseCpp2PrimaryExpression();
  bool atCpp2PostfixOperator(CurrentToken) const;
  bool parseCpp2PostfixOperator();
  void parseCpp2PostfixExpression();
  bool atCpp2ParameterDirection(CurrentToken) const;
  bool parseCpp2ParameterDirection();
  bool parseCpp2PrefixOperator();
  void parseCpp2PrefixExpression();
  void parseCpp2IsAsExpressionTarget();
  void parseCpp2IsAsExpression();
  bool atCpp2BinaryOperator(CurrentToken, prec::Level) const;
  bool parseCpp2BinaryOperator(prec::Level);
  void parseCpp2BinaryExpression(prec::Level);
  void parseCpp2LogicalOrExpression();
  void parseCpp2AssignmentExpression();
  void parseCpp2Expression();
  bool atCpp2AltName(CurrentToken) const;
  void parseCpp2AltName();
  void parseCpp2Alternative();
  auto setupCpp2InspectExpressionFormatting();
  void parseCpp2InspectExpression();
  auto setupCpp2CompoundStatementFormatting();
  void parseCpp2CompoundStatement();
  void parseCpp2SelectionStatement();
  void parseCpp2UsingStatement();
  void parseCpp2ReturnStatement();
  void parseCpp2JumpStatement();
  void parseCpp2NextClause();
  void parseCpp2WhileStatement();
  void parseCpp2DoStatement();
  bool atCpp2ParameterizedStatement(CurrentToken);
  void parseCpp2ParameterizedStatement();
  void parseCpp2ForStatement();
  bool atCpp2LabelIdentifier(CurrentToken);
  bool parseCpp2Label();
  void parseCpp2IterationStatementWithoutLabel();
  void parseCpp2ExpressionStatement();
  bool atCpp2Contract(CurrentToken) const;
  void parseCpp2Contract();
  void parseCpp2ContractStatement();
  void parseCpp2Statement();
  void parseCpp2MetaFunctionsList();
  bool precedesCpp2Identifier(CurrentToken) const;
  bool atCpp2ThisSpecifier(CurrentToken) const;
  void parseCpp2ThisSpecifier();
  auto atCpp2ParameterDeclarationHead(CurrentToken);
  void parseCpp2ParameterDeclaration();
  bool skipCpp2BalancedTokens(CurrentToken &);
  CurrentToken skipCpp2DeclarationSignature(CurrentToken,
                                            tok::TokenKind Closer);
  Cpp2ListOf atCpp2ParameterDeclarationSeq(CurrentToken, tok::TokenKind Opener);
  void parseCpp2ParameterDeclarationSeq(Cpp2Punctuator Opener);
  Cpp2ListOf atCpp2TemplateParameterDeclarationList(CurrentToken);
  auto setupCpp2TemplateParameterDeclarationListFormatting();
  void parseCpp2TemplateParameterDeclarationList();
  Cpp2ListOf atCpp2ParameterDeclarationList(CurrentToken);
  void parseCpp2ParameterDeclarationList();
  void parseCpp2ThrowsSpecifier();
  void parseCpp2ReturnList();
  void parseCpp2ContractSeq();
  bool atCpp2FunctionType(CurrentToken, Cpp2ListOf);
  bool parseCpp2FunctionType(Cpp2ListOf Expected = Cpp2ListOf::Undecided);
  bool parseCpp2TypeOrNamespace();
  bool atCpp2AccessSpecifier(CurrentToken) const;
  void parseCpp2AccessSpecifier();
  auto setupCpp2RequiresClauseFormatting();
  void parseCpp2RequiresClause();
  void parseCpp2DeclarationBinaryOperator();
  void parseCpp2UnnamedDeclaration();
  auto atCpp2DeclarationHead(CurrentToken);
  void parseCpp2DeclarationHead();
  Cpp2ParsedDeclarationSignature parseCpp2DeclarationSignature();
  auto
      setupCpp2DeclarationInitializerFormatting(Cpp2ParsedDeclarationSignature);
  void parseCpp2DeclarationInitializer(Cpp2ParsedDeclarationSignature);
  bool atCpp2Declaration();
  void parseCpp2Declaration();
  bool atCpp2TopLevelDeclaration();
  void parseCpp2TopLevelDeclaration();
  void parseJavaEnumBody();
  // Parses a record (aka class) as a top level element. If ParseAsExpr is true,
  // parses the record as a child block, i.e. if the class declaration is an
  // expression.
  void parseRecord(bool ParseAsExpr = false);
  void parseObjCLightweightGenerics();
  void parseObjCMethod();
  void parseObjCProtocolList();
  void parseObjCUntilAtEnd();
  void parseObjCInterfaceOrImplementation();
  bool parseObjCProtocol();
  void parseJavaScriptEs6ImportExport();
  void parseStatementMacro();
  void parseCSharpAttribute();
  // Parse a C# generic type constraint: `where T : IComparable<T>`.
  // See:
  // https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/where-generic-type-constraint
  void parseCSharpGenericTypeConstraint();
  bool tryToParseLambda();
  bool tryToParseChildBlock();
  bool tryToParseLambdaIntroducer();
  bool tryToParsePropertyAccessor();
  void tryToParseJSFunction();
  bool tryToParseSimpleAttribute();
  void parseVerilogHierarchyIdentifier();
  void parseVerilogSensitivityList();
  // Returns the number of levels of indentation in addition to the normal 1
  // level for a block, used for indenting case labels.
  unsigned parseVerilogHierarchyHeader();
  void parseVerilogTable();
  void parseVerilogCaseLabel();
  std::optional<llvm::SmallVector<llvm::SmallVector<FormatToken *, 8>, 1>>
  parseMacroCall();

  // Used by addUnwrappedLine to denote whether to keep or remove a level
  // when resetting the line state.
  enum class LineLevel { Remove, Keep };

  void addUnwrappedLine(LineLevel AdjustLevel = LineLevel::Remove);
  bool eof() const;
  // LevelDifference is the difference of levels after and before the current
  // token. For example:
  // - if the token is '{' and opens a block, LevelDifference is 1.
  // - if the token is '}' and closes a block, LevelDifference is -1.
  void nextToken(int LevelDifference = 0);
  void readToken(int LevelDifference = 0);

  // Decides which comment tokens should be added to the current line and which
  // should be added as comments before the next token.
  //
  // Comments specifies the sequence of comment tokens to analyze. They get
  // either pushed to the current line or added to the comments before the next
  // token.
  //
  // NextTok specifies the next token. A null pointer NextTok is supported, and
  // signifies either the absence of a next token, or that the next token
  // shouldn't be taken into account for the analysis.
  void distributeComments(const SmallVectorImpl<FormatToken *> &Comments,
                          const FormatToken *NextTok);

  // Adds the comment preceding the next token to unwrapped lines.
  void flushComments(bool NewlineBeforeNext);
  void pushToken(FormatToken *Tok);
  void calculateBraceTypes(bool ExpectClassBody = false);
  void setPreviousRBraceType(TokenType Type);

  // Marks a conditional compilation edge (for example, an '#if', '#ifdef',
  // '#else' or merge conflict marker). If 'Unreachable' is true, assumes
  // this branch either cannot be taken (for example '#if false'), or should
  // not be taken in this round.
  void conditionalCompilationCondition(bool Unreachable);
  void conditionalCompilationStart(bool Unreachable);
  void conditionalCompilationAlternative();
  void conditionalCompilationEnd();

  bool isOnNewLine(const FormatToken &FormatTok);

  // Returns whether there is a macro expansion in the line, i.e. a token that
  // was expanded from a macro call.
  bool containsExpansion(const UnwrappedLine &Line) const;

  // Compute hash of the current preprocessor branch.
  // This is used to identify the different branches, and thus track if block
  // open and close in the same branch.
  size_t computePPHash() const;

  bool parsingPPDirective() const { return CurrentLines != &Lines; }

  // FIXME: We are constantly running into bugs where Line.Level is incorrectly
  // subtracted from beyond 0. Introduce a method to subtract from Line.Level
  // and use that everywhere in the Parser.
  std::unique_ptr<UnwrappedLine> Line;

  // Lines that are created by macro expansion.
  // When formatting code containing macro calls, we first format the expanded
  // lines to set the token types correctly. Afterwards, we format the
  // reconstructed macro calls, re-using the token types determined in the first
  // step.
  // ExpandedLines will be reset every time we create a new LineAndExpansion
  // instance once a line containing macro calls has been parsed.
  SmallVector<UnwrappedLine, 8> CurrentExpandedLines;

  // Maps from the first token of a top-level UnwrappedLine that contains
  // a macro call to the replacement UnwrappedLines expanded from the macro
  // call.
  llvm::DenseMap<FormatToken *, SmallVector<UnwrappedLine, 8>> ExpandedLines;

  // Map from the macro identifier to a line containing the full unexpanded
  // macro call.
  llvm::DenseMap<FormatToken *, std::unique_ptr<UnwrappedLine>> Unexpanded;

  // For recursive macro expansions, trigger reconstruction only on the
  // outermost expansion.
  bool InExpansion = false;

  // Set while we reconstruct a macro call.
  // For reconstruction, we feed the expanded lines into the reconstructor
  // until it is finished.
  std::optional<MacroCallReconstructor> Reconstruct;

  // Comments are sorted into unwrapped lines by whether they are in the same
  // line as the previous token, or not. If not, they belong to the next token.
  // Since the next token might already be in a new unwrapped line, we need to
  // store the comments belonging to that token.
  SmallVector<FormatToken *, 1> CommentsBeforeNextToken;
  FormatToken *FormatTok = nullptr;
  bool MustBreakBeforeNextToken;

  // The parsed lines. Only added to through \c CurrentLines.
  SmallVector<UnwrappedLine, 8> Lines;

  // Preprocessor directives are parsed out-of-order from other unwrapped lines.
  // Thus, we need to keep a list of preprocessor directives to be reported
  // after an unwrapped line that has been started was finished.
  SmallVector<UnwrappedLine, 4> PreprocessorDirectives;

  // New unwrapped lines are added via CurrentLines.
  // Usually points to \c &Lines. While parsing a preprocessor directive when
  // there is an unfinished previous unwrapped line, will point to
  // \c &PreprocessorDirectives.
  SmallVectorImpl<UnwrappedLine> *CurrentLines;

  // We store for each line whether it must be a declaration depending on
  // whether we are in a compound statement or not.
  llvm::BitVector DeclarationScopeStack;

  const FormatStyle &Style;
  bool IsCpp;
  LangOptions LangOpts;
  const AdditionalKeywords &Keywords;

  llvm::Regex CommentPragmasRegex;

  FormatTokenSource *Tokens;
  UnwrappedLineConsumer &Callback;

  ArrayRef<FormatToken *> AllTokens;

  // Keeps a stack of the states of nested control statements (true if the
  // statement contains more than some predefined number of nested statements).
  SmallVector<bool, 8> NestedTooDeep;

  // Keeps a stack of the states of nested lambdas (true if the return type of
  // the lambda is `decltype(auto)`).
  SmallVector<bool, 4> NestedLambdas;

  // Whether the parser is parsing the body of a function whose return type is
  // `decltype(auto)`.
  bool IsDecltypeAutoFunction = false;

  // Represents preprocessor branch type, so we can find matching
  // #if/#else/#endif directives.
  enum PPBranchKind {
    PP_Conditional, // Any #if, #ifdef, #ifndef, #elif, block outside #if 0
    PP_Unreachable  // #if 0 or a conditional preprocessor block inside #if 0
  };

  struct PPBranch {
    PPBranch(PPBranchKind Kind, size_t Line) : Kind(Kind), Line(Line) {}
    PPBranchKind Kind;
    size_t Line;
  };

  // Keeps a stack of currently active preprocessor branching directives.
  SmallVector<PPBranch, 16> PPStack;

  // The \c UnwrappedLineParser re-parses the code for each combination
  // of preprocessor branches that can be taken.
  // To that end, we take the same branch (#if, #else, or one of the #elif
  // branches) for each nesting level of preprocessor branches.
  // \c PPBranchLevel stores the current nesting level of preprocessor
  // branches during one pass over the code.
  int PPBranchLevel;

  // Contains the current branch (#if, #else or one of the #elif branches)
  // for each nesting level.
  SmallVector<int, 8> PPLevelBranchIndex;

  // Contains the maximum number of branches at each nesting level.
  SmallVector<int, 8> PPLevelBranchCount;

  // Contains the number of branches per nesting level we are currently
  // in while parsing a preprocessor branch sequence.
  // This is used to update PPLevelBranchCount at the end of a branch
  // sequence.
  std::stack<int> PPChainBranchIndex;

  // Include guard search state. Used to fixup preprocessor indent levels
  // so that include guards do not participate in indentation.
  enum IncludeGuardState {
    IG_Inited,   // Search started, looking for #ifndef.
    IG_IfNdefed, // #ifndef found, IncludeGuardToken points to condition.
    IG_Defined,  // Matching #define found, checking other requirements.
    IG_Found,    // All requirements met, need to fix indents.
    IG_Rejected, // Search failed or never started.
  };

  // Current state of include guard search.
  IncludeGuardState IncludeGuard;

  // Points to the #ifndef condition for a potential include guard. Null unless
  // IncludeGuardState == IG_IfNdefed.
  FormatToken *IncludeGuardToken;

  // Contains the first start column where the source begins. This is zero for
  // normal source code and may be nonzero when formatting a code fragment that
  // does not start at the beginning of the file.
  unsigned FirstStartColumn;

  MacroExpander Macros;

  friend class ScopedLineState;
  friend class CompoundStatementIndenter;
};

struct UnwrappedLineNode {
  UnwrappedLineNode() : Tok(nullptr) {}
  UnwrappedLineNode(FormatToken *Tok,
                    llvm::ArrayRef<UnwrappedLine> Children = {})
      : Tok(Tok), Children(Children) {}

  FormatToken *Tok;
  SmallVector<UnwrappedLine, 0> Children;
};

std::ostream &operator<<(std::ostream &Stream, const UnwrappedLine &Line);

} // end namespace format
} // end namespace clang

#endif
