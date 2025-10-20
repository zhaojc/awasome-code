org.springframework.ai.chat.client.advisor.RetrievalAugmentationAdvisor
//异步任务
public AdvisedRequest before(AdvisedRequest request) {
		Map<String, Object> context = new HashMap<>(request.adviseContext());

		// 0. Create a query from the user text, parameters, and conversation history.
		Query originalQuery = Query.builder()
			.text(new PromptTemplate(request.userText(), request.userParams()).render())
			.history(request.messages())
			.build();

		// 1. Transform original user query based on a chain of query transformers.
		Query transformedQuery = originalQuery;
		for (var queryTransformer : this.queryTransformers) {
			transformedQuery = queryTransformer.apply(transformedQuery);
		}

		// 2. Expand query into one or multiple queries.
		List<Query> expandedQueries = this.queryExpander != null ? this.queryExpander.expand(transformedQuery)
				: List.of(transformedQuery);

		// 3. Get similar documents for each query.
		Map<Query, List<List<Document>>> documentsForQuery = expandedQueries.stream()
			.map(query -> CompletableFuture.supplyAsync(() -> getDocumentsForQuery(query), this.taskExecutor))
			.toList()
			.stream()
			.map(CompletableFuture::join)
			.collect(Collectors.toMap(Map.Entry::getKey, entry -> List.of(entry.getValue())));

		// 4. Combine documents retrieved based on multiple queries and from multiple data
		// sources.
		List<Document> documents = this.documentJoiner.join(documentsForQuery);
		context.put(DOCUMENT_CONTEXT, documents);

		// 5. Augment user query with the document contextual data.
		Query augmentedQuery = this.queryAugmenter.augment(originalQuery, documents);

		// 6. Update advised request with augmented prompt.
		return AdvisedRequest.from(request).userText(augmentedQuery.text()).adviseContext(context).build();
	}  


public class QueryParameters {

    @QueryValue("values")
    private final Map<String, String> parameters;

    public QueryParameters(Map<String, String> parameters) {
        this.parameters = parameters;
    }

    public Map<String, String> getParameters() {
        return parameters;
    }

    @Override
    public String toString() {
        return parameters.entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining(", ", "{", "}"));
    }
}

//动态条件构建
public class FilterExpressionBuilder {

	public Op eq(String key, Object value) {
		return new Op(new Filter.Expression(ExpressionType.EQ, new Key(key), new Value(value)));
	}

	public Op ne(String key, Object value) {
		return new Op(new Filter.Expression(ExpressionType.NE, new Key(key), new Value(value)));
	}

	public Op gt(String key, Object value) {
		return new Op(new Filter.Expression(ExpressionType.GT, new Key(key), new Value(value)));
	}

	public Op gte(String key, Object value) {
		return new Op(new Filter.Expression(ExpressionType.GTE, new Key(key), new Value(value)));
	}

	public Op lt(String key, Object value) {
		return new Op(new Filter.Expression(ExpressionType.LT, new Key(key), new Value(value)));
	}

	public Op lte(String key, Object value) {
		return new Op(new Filter.Expression(ExpressionType.LTE, new Key(key), new Value(value)));
	}

	public Op and(Op left, Op right) {
		return new Op(new Filter.Expression(ExpressionType.AND, left.expression, right.expression));
	}

	public Op or(Op left, Op right) {
		return new Op(new Filter.Expression(ExpressionType.OR, left.expression, right.expression));
	}

	public Op in(String key, Object... values) {
		return this.in(key, List.of(values));
	}

	public Op in(String key, List<Object> values) {
		return new Op(new Filter.Expression(ExpressionType.IN, new Key(key), new Value(values)));
	}

	public Op nin(String key, Object... values) {
		return this.nin(key, List.of(values));
	}

	public Op nin(String key, List<Object> values) {
		return new Op(new Filter.Expression(ExpressionType.NIN, new Key(key), new Value(values)));
	}

	public Op group(Op content) {
		return new Op(new Filter.Group(content.build()));
	}

	public Op not(Op content) {
		return new Op(new Filter.Expression(ExpressionType.NOT, content.expression, null));
	}

	public record Op(Filter.Operand expression) {

		public Filter.Expression build() {
			if (this.expression instanceof Filter.Group group) {
				// Remove the top-level grouping.
				return group.content();
			}
			else if (this.expression instanceof Filter.Expression exp) {
				return exp;
			}
			throw new RuntimeException("Invalid expression: " + this.expression);
		}

	}

}


//链式流程定义
private ApiCall<ApiResponse<AlbumObject>, ApiException> prepareGetAnAlbumRequest(
            final String id,
            final String market) throws IOException {
        return new ApiCall.Builder<ApiResponse<AlbumObject>, ApiException>()
                .globalConfig(getGlobalConfiguration())
                .requestBuilder(requestBuilder -> requestBuilder
                        .server(Server.ENUM_DEFAULT.value())
                        .path("/albums/{id}")
                        .queryParam(param -> param.key("market")
                                .value(market).isRequired(false))
                        .templateParam(param -> param.key("id").value(id)
                                .shouldEncode(true))
                        .headerParam(param -> param.key("accept").value("application/json"))
                        .withAuth(auth -> auth
                                .add("oauth_2_0"))
                        .arraySerializationFormat(ArraySerializationFormat.CSV)
                        .httpMethod(HttpMethod.GET)
                )
                .responseHandler(responseHandler -> responseHandler
                        .responseClassType(ResponseClassType.API_RESPONSE)
                        .apiResponseDeserializer(
                                response -> ApiHelper.deserialize(response, AlbumObject.class))
                        .nullify404(false)
                        .localErrorCase("401",
                                ErrorCase.setReason("Bad or expired token. This can happen if the user revoked a token or\nthe access token has expired. You should re-authenticate the user.\n",
                                        (reason, context) -> new UnauthorizedException(reason, context)))
                        .localErrorCase("403",
                                ErrorCase.setReason("Bad OAuth request (wrong consumer key, bad nonce, expired\ntimestamp...). Unfortunately, re-authenticating the user won't help here.\n",
                                        (reason, context) -> new ForbiddenException(reason, context)))
                        .localErrorCase("429",
                                ErrorCase.setReason("The app has exceeded its rate limits.\n",
                                        (reason, context) -> new TooManyRequestsException(reason, context)))
                        .globalErrorCase(GLOBAL_ERROR_CASES))
                .build();
    }

 //user请求自动符值
  @Bean
  @Scope(value = WebApplicationContext.SCOPE_REQUEST, proxyMode = ScopedProxyMode.TARGET_CLASS)
  public User.UserBuilder callerBuilder() {
    return User.builder();
  }

//factory返回值不固定
public interface HttpClientFactory<T> {

    T create(HttpClientSettings settings);

}
//aws-sdk-java
public class ApacheHttpClientFactory implements HttpClientFactory<ConnectionManagerAwareHttpClient> {
}

//eventstore expression
   void testSelectWhere() {
        SelectBuilder builder = new SelectBuilder(database, of(COL_T1_01, COL_T1_02, COL_T1_03));
        builder.from(TABLE_T1);
        builder.where(eq(COL_T1_02));
        assertEquals("SELECT col_T1_01,col_T1_02,col_T1_03 FROM T1 WHERE col_T1_02=?", builder.<SqlQuery>build().sql());

        builder = new SelectBuilder(database, of(COL_T1_01, COL_T1_02, COL_T1_03));
        builder.from(TABLE_T1);
        builder.where(and(eq(COL_T1_02), eq(COL_T1_03)));
        assertEquals("SELECT col_T1_01,col_T1_02,col_T1_03 FROM T1 WHERE (col_T1_02=? AND col_T1_03=?)", builder.<SqlQuery>build().sql());
    }

//enenvstrorm antlr4
    public static PageRequest parse(String query, EvaluatorDefinition evaluatorDefinition) {

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("parseQuery [{}]", query);
        }

        if (Strings.isEmpty(query)) {
            throw new PageRequestException(PageRequestException.Type.EMPTY, ImmutableMap.of());
        }

        RequestContext ctx = parse(query);

        PageRequestBuilder builder = parseRange(query, ctx.range());
        parseFilter(builder, ctx.filter(), evaluatorDefinition);
        parseSort(builder, ctx.sort());

        builder.withEvaluator(evaluatorDefinition);

        return builder.build();
    }


//retry
public class RetryUtility {
    
    private final int maxRetries;
    private final Duration initialDelay;
    private final double backoffMultiplier;
    private final Duration maxDelay;
    private final Predicate<Exception> retryCondition;
    
    public RetryUtility(int maxRetries, Duration initialDelay, double backoffMultiplier, 
                       Duration maxDelay, Predicate<Exception> retryCondition) {
        this.maxRetries = maxRetries;
        this.initialDelay = initialDelay;
        this.backoffMultiplier = backoffMultiplier;
        this.maxDelay = maxDelay;
        this.retryCondition = retryCondition;
    }
    
    public static RetryUtility defaultNetworkRetry() {
        return new RetryUtility(
            3,
            Duration.ofMillis(1000),
            2.0,
            Duration.ofSeconds(30),
            e -> e instanceof IOException || e instanceof RuntimeException
        );
    }
    
    public <T> T execute(Callable<T> operation) throws Exception {
        Exception lastException = null;
        Duration currentDelay = initialDelay;
        
        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                System.out.println("Attempt " + (attempt + 1) + "/" + (maxRetries + 1));
                return operation.call();
            } catch (Exception e) {
                lastException = e;
                
                if (attempt == maxRetries || !retryCondition.test(e)) {
                    System.err.println("Max retries reached or non-retryable exception. Giving up.");
                    throw e;
                }
                
                System.err.println("Attempt " + (attempt + 1) + " failed: " + e.getMessage());
                System.out.println("Retrying in " + currentDelay.toMillis() + "ms...");
                
                try {
                    Thread.sleep(currentDelay.toMillis());
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException("Retry interrupted", ie);
                }
                
                // Calculate next delay with exponential backoff
                currentDelay = Duration.ofMillis(
                    Math.min((long)(currentDelay.toMillis() * backoffMultiplier), maxDelay.toMillis())
                );
            }
        }
        
        throw lastException;
    }
    
    // Simulate network service
    static class NetworkService {
        private static final Random random = new Random();
        private int callCount = 0;
        
        public String makeNetworkCall() throws IOException {
            callCount++;
            
            // Simulate network failures
            if (callCount <= 2 && random.nextBoolean()) {
                throw new IOException("Network timeout - attempt " + callCount);
            }
            
            return "Success after " + callCount + " attempts";
        }
    }
    
    public static void main(String[] args) {
        RetryUtility retry = RetryUtility.defaultNetworkRetry();
        NetworkService service = new NetworkService();
        
        try {
            String result = retry.execute(service::makeNetworkCall);
            System.out.println("Result: " + result);
        } catch (Exception e) {
            System.err.println("Final failure: " + e.getMessage());
        }
    }
}

//spring configuration类先执行autowrited再执行初始化bean


@Configuration(proxyBeanMethods = false)
public class WebSecurityConfiguration implements ImportAware, BeanClassLoaderAware {

	private WebSecurity webSecurity;

	private Boolean debugEnabled;

	private List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers;

	private List<SecurityFilterChain> securityFilterChains = Collections.emptyList();

	private List<WebSecurityCustomizer> webSecurityCustomizers = Collections.emptyList();

	private ClassLoader beanClassLoader;

	@Autowired(required = false)
	private ObjectPostProcessor<Object> objectObjectPostProcessor;

	@Autowired(required = false)
	private HttpSecurity httpSecurity;

	@Bean
	public static DelegatingApplicationListener delegatingApplicationListener() {
		return new DelegatingApplicationListener();
	}

	@Bean
	@DependsOn(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public SecurityExpressionHandler<FilterInvocation> webSecurityExpressionHandler() {
		return this.webSecurity.getExpressionHandler();
	}

	/**
	 * Creates the Spring Security Filter Chain
	 * @return the {@link Filter} that represents the security filter chain
	 * @throws Exception
	 */
	@Bean(name = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public Filter springSecurityFilterChain() throws Exception {
		boolean hasFilterChain = !this.securityFilterChains.isEmpty();
		if (!hasFilterChain) {
			this.webSecurity.addSecurityFilterChainBuilder(() -> {
				this.httpSecurity.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated());
				this.httpSecurity.formLogin(Customizer.withDefaults());
				this.httpSecurity.httpBasic(Customizer.withDefaults());
				return this.httpSecurity.build();
			});
		}
		for (SecurityFilterChain securityFilterChain : this.securityFilterChains) {
			this.webSecurity.addSecurityFilterChainBuilder(() -> securityFilterChain);
		}
		for (WebSecurityCustomizer customizer : this.webSecurityCustomizers) {
			customizer.customize(this.webSecurity);
		}
		return this.webSecurity.build();
	}

	/**
	 * Creates the {@link WebInvocationPrivilegeEvaluator} that is necessary to evaluate
	 * privileges for a given web URI
	 * @return the {@link WebInvocationPrivilegeEvaluator}
	 */
	@Bean
	@DependsOn(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public WebInvocationPrivilegeEvaluator privilegeEvaluator() {
		return this.webSecurity.getPrivilegeEvaluator();
	}

	/**
	 * Sets the {@code <SecurityConfigurer<FilterChainProxy, WebSecurityBuilder>}
	 * instances used to create the web configuration.
	 * @param objectPostProcessor the {@link ObjectPostProcessor} used to create a
	 * {@link WebSecurity} instance
	 * @param beanFactory the bean factory to use to retrieve the relevant
	 * {@code <SecurityConfigurer<FilterChainProxy, WebSecurityBuilder>} instances used to
	 * create the web configuration
	 * @throws Exception
	 */
	@Autowired(required = false)
	public void setFilterChainProxySecurityConfigurer(ObjectPostProcessor<Object> objectPostProcessor,
			ConfigurableListableBeanFactory beanFactory) throws Exception {
		this.webSecurity = objectPostProcessor.postProcess(new WebSecurity(objectPostProcessor));
		if (this.debugEnabled != null) {
			this.webSecurity.debug(this.debugEnabled);
		}
		List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers = new AutowiredWebSecurityConfigurersIgnoreParents(
				beanFactory)
			.getWebSecurityConfigurers();
		webSecurityConfigurers.sort(AnnotationAwareOrderComparator.INSTANCE);
		Integer previousOrder = null;
		Object previousConfig = null;
		for (SecurityConfigurer<Filter, WebSecurity> config : webSecurityConfigurers) {
			Integer order = AnnotationAwareOrderComparator.lookupOrder(config);
			if (previousOrder != null && previousOrder.equals(order)) {
				throw new IllegalStateException("@Order on WebSecurityConfigurers must be unique. Order of " + order
						+ " was already used on " + previousConfig + ", so it cannot be used on " + config + " too.");
			}
			previousOrder = order;
			previousConfig = config;
		}
		for (SecurityConfigurer<Filter, WebSecurity> webSecurityConfigurer : webSecurityConfigurers) {
			this.webSecurity.apply(webSecurityConfigurer);
		}
		this.webSecurityConfigurers = webSecurityConfigurers;
	}

	@Autowired(required = false)
	void setFilterChains(List<SecurityFilterChain> securityFilterChains) {
		this.securityFilterChains = securityFilterChains;
	}

	@Autowired(required = false)
	void setWebSecurityCustomizers(List<WebSecurityCustomizer> webSecurityCustomizers) {
		this.webSecurityCustomizers = webSecurityCustomizers;
	}

	@Bean
	public static BeanFactoryPostProcessor conversionServicePostProcessor() {
		return new RsaKeyConversionServicePostProcessor();
	}

	@Override
	public void setImportMetadata(AnnotationMetadata importMetadata) {
		Map<String, Object> enableWebSecurityAttrMap = importMetadata
			.getAnnotationAttributes(EnableWebSecurity.class.getName());
		AnnotationAttributes enableWebSecurityAttrs = AnnotationAttributes.fromMap(enableWebSecurityAttrMap);
		this.debugEnabled = enableWebSecurityAttrs.getBoolean("debug");
		if (this.webSecurity != null) {
			this.webSecurity.debug(this.debugEnabled);
		}
	}

	@Override
	public void setBeanClassLoader(ClassLoader classLoader) {
		this.beanClassLoader = classLoader;
	}

	/**
	 * A custom version of the Spring provided AnnotationAwareOrderComparator that uses
	 * {@link AnnotationUtils#findAnnotation(Class, Class)} to look on super class
	 * instances for the {@link Order} annotation.
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	private static class AnnotationAwareOrderComparator extends OrderComparator {

		private static final AnnotationAwareOrderComparator INSTANCE = new AnnotationAwareOrderComparator();

		@Override
		protected int getOrder(Object obj) {
			return lookupOrder(obj);
		}

		private static int lookupOrder(Object obj) {
			if (obj instanceof Ordered) {
				return ((Ordered) obj).getOrder();
			}
			if (obj != null) {
				Class<?> clazz = ((obj instanceof Class) ? (Class<?>) obj : obj.getClass());
				Order order = AnnotationUtils.findAnnotation(clazz, Order.class);
				if (order != null) {
					return order.value();
				}
			}
			return Ordered.LOWEST_PRECEDENCE;
		}

	}

}

public final class JdbcOneTimeTokenService implements OneTimeTokenService, DisposableBean, InitializingBean {

	private final Log logger = LogFactory.getLog(getClass());

	private final JdbcOperations jdbcOperations;

	private Function<OneTimeToken, List<SqlParameterValue>> oneTimeTokenParametersMapper = new OneTimeTokenParametersMapper();

	private RowMapper<OneTimeToken> oneTimeTokenRowMapper = new OneTimeTokenRowMapper();

	private Clock clock = Clock.systemUTC();

	private ThreadPoolTaskScheduler taskScheduler;

	private static final String DEFAULT_CLEANUP_CRON = "@hourly";

	private static final String TABLE_NAME = "one_time_tokens";

	// @formatter:off
	private static final String COLUMN_NAMES = "token_value, "
			+ "username, "
			+ "expires_at";
	// @formatter:on

	// @formatter:off
	private static final String SAVE_ONE_TIME_TOKEN_SQL = "INSERT INTO " + TABLE_NAME
			+ " (" + COLUMN_NAMES + ") VALUES (?, ?, ?)";
	// @formatter:on

	private static final String FILTER = "token_value = ?";

	private static final String DELETE_ONE_TIME_TOKEN_SQL = "DELETE FROM " + TABLE_NAME + " WHERE " + FILTER;

	// @formatter:off
	private static final String SELECT_ONE_TIME_TOKEN_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + FILTER;
	// @formatter:on

	// @formatter:off
	private static final String DELETE_ONE_TIME_TOKENS_BY_EXPIRY_TIME_QUERY = "DELETE FROM "
			+ TABLE_NAME
			+ " WHERE expires_at < ?";
	// @formatter:on

	/**
	 * Constructs a {@code JdbcOneTimeTokenService} using the provide parameters.
	 * @param jdbcOperations the JDBC operations
	 */
	public JdbcOneTimeTokenService(JdbcOperations jdbcOperations) {
		Assert.notNull(jdbcOperations, "jdbcOperations cannot be null");
		this.jdbcOperations = jdbcOperations;
		this.taskScheduler = createTaskScheduler(DEFAULT_CLEANUP_CRON);
	}

	/**
	 * Sets the chron expression used for cleaning up expired tokens. The default is to
	 * run hourly.
	 *
	 * For more advanced use cases the cleanupCron may be set to null which will disable
	 * the built-in cleanup. Users can then invoke {@link #cleanupExpiredTokens()} using
	 * custom logic.
	 * @param cleanupCron the chron expression passed to {@link CronTrigger} used for
	 * determining how frequent to perform cleanup. The default is "@hourly".
	 * @see CronTrigger
	 * @see #cleanupExpiredTokens()
	 */
	public void setCleanupCron(String cleanupCron) {
		this.taskScheduler = createTaskScheduler(cleanupCron);
	}

	@Override
	public OneTimeToken generate(GenerateOneTimeTokenRequest request) {
		Assert.notNull(request, "generateOneTimeTokenRequest cannot be null");
		String token = UUID.randomUUID().toString();
		Instant expiresAt = this.clock.instant().plus(request.getExpiresIn());
		OneTimeToken oneTimeToken = new DefaultOneTimeToken(token, request.getUsername(), expiresAt);
		insertOneTimeToken(oneTimeToken);
		return oneTimeToken;
	}

	private void insertOneTimeToken(OneTimeToken oneTimeToken) {
		List<SqlParameterValue> parameters = this.oneTimeTokenParametersMapper.apply(oneTimeToken);
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		this.jdbcOperations.update(SAVE_ONE_TIME_TOKEN_SQL, pss);
	}

	@Override
	public OneTimeToken consume(OneTimeTokenAuthenticationToken authenticationToken) {
		Assert.notNull(authenticationToken, "authenticationToken cannot be null");

		List<OneTimeToken> tokens = selectOneTimeToken(authenticationToken);
		if (CollectionUtils.isEmpty(tokens)) {
			return null;
		}
		OneTimeToken token = tokens.get(0);
		deleteOneTimeToken(token);
		if (isExpired(token)) {
			return null;
		}
		return token;
	}

	private boolean isExpired(OneTimeToken ott) {
		return this.clock.instant().isAfter(ott.getExpiresAt());
	}

	private List<OneTimeToken> selectOneTimeToken(OneTimeTokenAuthenticationToken authenticationToken) {
		List<SqlParameterValue> parameters = List
			.of(new SqlParameterValue(Types.VARCHAR, authenticationToken.getTokenValue()));
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		return this.jdbcOperations.query(SELECT_ONE_TIME_TOKEN_SQL, pss, this.oneTimeTokenRowMapper);
	}

	private void deleteOneTimeToken(OneTimeToken oneTimeToken) {
		List<SqlParameterValue> parameters = List
			.of(new SqlParameterValue(Types.VARCHAR, oneTimeToken.getTokenValue()));
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		this.jdbcOperations.update(DELETE_ONE_TIME_TOKEN_SQL, pss);
	}

	private ThreadPoolTaskScheduler createTaskScheduler(String cleanupCron) {
		if (cleanupCron == null) {
			return null;
		}
		ThreadPoolTaskScheduler taskScheduler = new ThreadPoolTaskScheduler();
		taskScheduler.setThreadNamePrefix("spring-one-time-tokens-");
		taskScheduler.initialize();
		taskScheduler.schedule(this::cleanupExpiredTokens, new CronTrigger(cleanupCron));
		return taskScheduler;
	}

	public void cleanupExpiredTokens() {
		List<SqlParameterValue> parameters = List
			.of(new SqlParameterValue(Types.TIMESTAMP, Timestamp.from(Instant.now())));
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		int deletedCount = this.jdbcOperations.update(DELETE_ONE_TIME_TOKENS_BY_EXPIRY_TIME_QUERY, pss);
		if (this.logger.isDebugEnabled()) {
			this.logger.debug("Cleaned up " + deletedCount + " expired tokens");
		}
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		this.taskScheduler.afterPropertiesSet();
	}

	@Override
	public void destroy() throws Exception {
		if (this.taskScheduler != null) {
			this.taskScheduler.shutdown();
		}
	}

	/**
	 * Sets the {@link Clock} used when generating one-time token and checking token
	 * expiry.
	 * @param clock the clock
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

	/**
	 * The default {@code Function} that maps {@link OneTimeToken} to a {@code List} of
	 * {@link SqlParameterValue}.
	 *
	 * @author Max Batischev
	 * @since 6.4
	 */
	private static class OneTimeTokenParametersMapper implements Function<OneTimeToken, List<SqlParameterValue>> {

		@Override
		public List<SqlParameterValue> apply(OneTimeToken oneTimeToken) {
			List<SqlParameterValue> parameters = new ArrayList<>();
			parameters.add(new SqlParameterValue(Types.VARCHAR, oneTimeToken.getTokenValue()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, oneTimeToken.getUsername()));
			parameters.add(new SqlParameterValue(Types.TIMESTAMP, Timestamp.from(oneTimeToken.getExpiresAt())));
			return parameters;
		}

	}

	/**
	 * The default {@link RowMapper} that maps the current row in
	 * {@code java.sql.ResultSet} to {@link OneTimeToken}.
	 *
	 * @author Max Batischev
	 * @since 6.4
	 */
	private static class OneTimeTokenRowMapper implements RowMapper<OneTimeToken> {

		@Override
		public OneTimeToken mapRow(ResultSet rs, int rowNum) throws SQLException {
			String tokenValue = rs.getString("token_value");
			String userName = rs.getString("username");
			Instant expiresAt = rs.getTimestamp("expires_at").toInstant();
			return new DefaultOneTimeToken(tokenValue, userName, expiresAt);
		}

	}

}

