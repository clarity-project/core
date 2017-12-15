<?php

/*
 * This file is part of the API Platform project.
 *
 * (c) Kévin Dunglas <dunglas@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace ApiPlatform\Core\Serializer;

use ApiPlatform\Core\Api\OperationType;
use ApiPlatform\Core\Exception\RuntimeException;
use ApiPlatform\Core\Metadata\Resource\Factory\ResourceMetadataFactoryInterface;
use ApiPlatform\Core\Security\ExpressionLanguage;
use ApiPlatform\Core\Util\RequestAttributesExtractor;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolverInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Role\Role;
use Symfony\Component\Security\Core\Role\RoleHierarchyInterface;

/**
 * {@inheritdoc}
 *
 * @author Kévin Dunglas <dunglas@gmail.com>
 */
final class SerializerContextBuilder implements SerializerContextBuilderInterface
{
    private $resourceMetadataFactory;
    private $expressionLanguage;
    private $authenticationTrustResolver;
    private $roleHierarchy;
    private $tokenStorage;
    private $authorizationChecker;

    public function __construct(
        ResourceMetadataFactoryInterface $resourceMetadataFactory,
        ExpressionLanguage $expressionLanguage = null,
        AuthenticationTrustResolverInterface $authenticationTrustResolver = null,
        RoleHierarchyInterface $roleHierarchy = null,
        TokenStorageInterface $tokenStorage = null,
        AuthorizationCheckerInterface $authorizationChecker = null
    ) {
        $this->resourceMetadataFactory = $resourceMetadataFactory;
        $this->expressionLanguage = $expressionLanguage;
        $this->authenticationTrustResolver = $authenticationTrustResolver;
        $this->roleHierarchy = $roleHierarchy;
        $this->tokenStorage = $tokenStorage;
        $this->authorizationChecker = $authorizationChecker;
    }

    /**
     * @param $resourceClass
     * @return array
     */
    protected function getVariables($resourceClass)
    {
        if (null === $this->tokenStorage || null === $this->authenticationTrustResolver) {
            throw new \LogicException(sprintf('The "symfony/security" library must be installed to use the "access_control" attribute on class "%s".', $resourceClass));
        }
        if (null === $this->tokenStorage->getToken()) {
            throw new \LogicException(sprintf('The resource must be behind a firewall to use the "access_control" attribute on class "%s".', $resourceClass));
        }
        if (null === $this->expressionLanguage) {
            throw new \LogicException(sprintf('The "symfony/expression-language" library must be installed to use the "access_control" attribute on class "%s".', $resourceClass));
        }

        $token = $this->tokenStorage->getToken();
        $roles = $this->roleHierarchy ? $this->roleHierarchy->getReachableRoles($token->getRoles()) : $token->getRoles();

        return [
            'token' => $token,
            'user' => $token->getUser(),
            'roles' => array_map(function (Role $role) {
                return $role->getRole();
            }, $roles),
            'trust_resolver' => $this->authenticationTrustResolver,
            // needed for the is_granted expression function
            'auth_checker' => $this->authorizationChecker,
        ];
    }

    /**
     * @param array $groups
     * @return array
     */
    protected function extractGroups(array $groups, $resourceClass)
    {
        $serializerGroups = [];
        foreach ($groups as $group => $groupConfiguration) {
            if (is_array($groupConfiguration)) {
                if (php_sapi_name() == 'cli') {
                    $serializerGroups[] = $group;
                } else if (array_key_exists('access_control', $groupConfiguration) &&
                    $this->expressionLanguage->evaluate($groupConfiguration['access_control'], $this->getVariables($resourceClass))
                ) {
                    $serializerGroups[] = $group;
                }
            } else {
                $serializerGroups[] = $groupConfiguration; // this means, that group was passed as simple string without configs
            }
        }

        return $serializerGroups;
    }

    /**
     * {@inheritdoc}
     */
    public function createFromRequest(Request $request, bool $normalization, array $attributes = null): array
    {
        if (null === $attributes && !$attributes = RequestAttributesExtractor::extractAttributes($request)) {
            throw new RuntimeException('Request attributes are not valid.');
        }

        $resourceMetadata = $this->resourceMetadataFactory->create($attributes['resource_class']);
        $key = $normalization ? 'normalization_context' : 'denormalization_context';

        $operationKey = null;
        $operationType = null;

        if (isset($attributes['collection_operation_name'])) {
            $operationKey = 'collection_operation_name';
            $operationType = OperationType::COLLECTION;
        } elseif (isset($attributes['subresource_operation_name'])) {
            $operationKey = 'subresource_operation_name';
            $operationType = OperationType::SUBRESOURCE;
        }

        if (null !== $operationKey) {
            $attribute = $attributes[$operationKey];
            $context = $resourceMetadata->getCollectionOperationAttribute($attribute, $key, [], true);
            $context[$operationKey] = $attribute;
        } else {
            $context = $resourceMetadata->getItemOperationAttribute($attributes['item_operation_name'], $key, [], true);
            $context['item_operation_name'] = $attributes['item_operation_name'];
        }

        $context['operation_type'] = $operationType ? $operationType : OperationType::ITEM;

        if (!$normalization && !isset($context['api_allow_update'])) {
            $context['api_allow_update'] = in_array($request->getMethod(), [Request::METHOD_PUT, Request::METHOD_PATCH], true);
        }

        $context['resource_class'] = $attributes['resource_class'];
        $context['request_uri'] = $request->getRequestUri();
        $context['uri'] = $request->getUri();

        if (isset($attributes['subresource_context'])) {
            $context['subresource_identifiers'] = [];

            foreach ($attributes['subresource_context']['identifiers'] as $key => list($id, $resourceClass)) {
                if (!isset($context['subresource_resources'][$resourceClass])) {
                    $context['subresource_resources'][$resourceClass] = [];
                }

                $context['subresource_identifiers'][$id] = $context['subresource_resources'][$resourceClass][$id] = $request->attributes->get($id);
            }
        }

        if (isset($attributes['subresource_property'])) {
            $context['subresource_property'] = $attributes['subresource_property'];
            $context['subresource_resource_class'] = $attributes['subresource_resource_class'] ?? null;
        }

        $resourceClass = $attributes['resource_class'];
        $context['groups'] = $this->extractGroups($context['groups'], $resourceClass);

        return $context;
    }
}
